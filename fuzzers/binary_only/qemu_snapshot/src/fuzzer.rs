//! Simple QEMU usermode snapshot harness:
//! - runs the target until a user‑provided address
//! - takes a memory snapshot there
//! - re‑executes from that snapshot for each input.

#![cfg(target_os = "linux")]

use core::time::Duration;
use std::{env, fs::DirEntry, io, path::PathBuf, process};

use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryCorpus},
    events::{SendExiting, SimpleRestartingEventManager, SimpleEventManager},
    executors::ExitKind,
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    schedulers::QueueScheduler,
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsSlice,
};
use libafl_qemu::{
    elf::EasyElf,
    modules::SnapshotModule, ArchExtras, Emulator, GuestAddr, GuestReg, MmapPerms, Qemu,
    QemuExecutor, QemuExitReason, QemuRWError, QemuShutdownCause, QemuHooks, Regs,
};
use log::info;

/// Maximum size of an input we write into the target buffer.
pub const MAX_INPUT_SIZE: usize = 1024 * 1024; // 1 MiB

/// Parse millis string to [`Duration`] (for clap).
fn timeout_from_millis_str(time: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(time.parse()?))
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(name = "qemu_snapshot", about = "QEMU usermode snapshot harness")]
pub struct SnapshotOptions {
    /// Directory with initial inputs.
    #[arg(long, help = "Input directory")]
    pub input_dir: PathBuf,

    /// Timeout per execution (in ms).
    #[arg(
        long,
        help = "Timeout in milliseconds",
        default_value = "5000",
        value_parser = timeout_from_millis_str
    )]
    pub timeout: Duration,

    /// Address at which to take the snapshot (hex, e.g. 0x401000).
    #[arg(long, help = "Guest address at which to create the snapshot (hex, e.g. 0x401000)")]
    pub snapshot_addr: String,

    /// Extra arguments passed to the target (after --).
    #[arg(last = true, help = "Arguments passed to the target under QEMU")]
    pub args: Vec<String>,
}

fn parse_snapshot_addr(s: &str) -> Result<GuestAddr, Error> {
    let cleaned = s.trim_start_matches("0x").trim_start_matches("0X");
    let addr = u64::from_str_radix(cleaned, 16)?;
    Ok(addr as GuestAddr)
}

unsafe extern "C" fn log_block_gen(_data: u64, pc: GuestAddr) -> u64 {
    // pc == guest pc
    eprintln!("[QEMU][TB_GEN] guest_pc = 0x{pc:x}");
    pc as u64
}

unsafe extern "C" fn log_block_exec(_data: u64, id: u64) {
    // id == guest_pc (위에서 넘긴 값)
    if let Some(q) = Qemu::get() {
        let current_pc: GuestReg = q.read_reg(Regs::Pc).unwrap();
        eprintln!(
            "[QEMU][TB_EXEC] guest_pc = 0x{id:x} (current_pc = 0x{current_pc:x})"
        );
    } else {
        eprintln!("[QEMU][TB_EXEC] guest_pc = 0x{id:x}");
    }
}

/// Run the snapshot harness.
pub fn run() -> Result<(), Error> {
    env_logger::init();

    let mut options = SnapshotOptions::parse();

    // Collect corpus files.
    let corpus_files = options
        .input_dir
        .read_dir()
        .expect("Failed to read corpus dir")
        .collect::<Result<Vec<DirEntry>, io::Error>>()
        .expect("Failed to read dir entry");

    if corpus_files.is_empty() {
        println!("No inputs in {:?}", options.input_dir);
        return Ok(());
    }

    // Build the QEMU argv: first arg must be current program path.
    let program = env::args().next().unwrap();
    info!("Program: {program}");
    options.args.insert(0, program);
    info!("Target ARGS: {:#?}", options.args);

    // We don't want LD_LIBRARY_PATH from host to leak into the target.
    env::remove_var("LD_LIBRARY_PATH");

    let snapshot_addr = parse_snapshot_addr(&options.snapshot_addr)?;
    info!("Snapshot address: 0x{snapshot_addr:x}");

    // Single‑process shmem/event manager.
    let mut shmem_provider = StdShMemProvider::new()?;
    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let (state, mut mgr) =
        match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider) {
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => return Ok(()),
                _ => return Err(err),
            },
        };

    // ----- QEMU / Emulator setup -----
    let modules = tuple_list!(SnapshotModule::new());

    let mut emulator = Emulator::empty()
        .qemu_parameters(options.args.clone())
        .modules(modules)
        .build()
        .expect("QEMU initialization failed");

    let qemu = emulator.qemu();
    
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;
    let model_malloc_max_addr = elf  
        .resolve_symbol("model_malloc_max", qemu.load_addr())  
        .expect("Symbol model_malloc_max not found");  
    info!("model_malloc_max @ 0x{model_malloc_max_addr:x}");
    let load = qemu.load_addr();
    eprintln!("[QEMU] load_addr = 0x{load:x}");
    
    qemu.entry_break(model_malloc_max_addr);

    // Install basic-block (translation block) logging hooks for debugging.
    if let Some(hooks) = QemuHooks::get() {
        unsafe {
            hooks.add_block_hooks(0u64, Some(log_block_gen), None, Some(log_block_exec));
        }
    } else {
        info!("QemuHooks not initialized; block logging disabled");
    }

    // Run to the snapshot address once, then let SnapshotModule snapshot that state
    // on the first `pre_exec` before fuzzing.
    info!("Running target until snapshot address 0x{snapshot_addr:x}");
    qemu.entry_break(snapshot_addr);

    unsafe {
        match qemu.run() {
            Ok(QemuExitReason::Breakpoint(addr)) => {
                info!("Reached snapshot breakpoint at 0x{addr:x}");
            }
            Ok(other) => {
                panic!("Unexpected QEMU exit while reaching snapshot point: {other:?}");
            }
            Err(e) => {
                panic!("QEMU error while reaching snapshot point: {e:?}");
            }
        }
    }


    // Save some registers and setup a private input buffer.
    let stack_ptr: GuestAddr = qemu.read_reg(Regs::Sp).unwrap();
    let ret_addr: GuestAddr = qemu.read_return_address().unwrap();
    info!("Return address from snapshot point = 0x{ret_addr:x}");

    // Break when the function at snapshot_addr returns.
    qemu.set_breakpoint(ret_addr);

    let input_addr = qemu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();
    info!("Input buffer mapped at 0x{input_addr:x}");

    // Helper to reset registers and memory for a single run, starting from the
    // snapshot location. SnapshotModule will restore memory before each exec;
    // here we restore registers and arguments.
    let reset = |qemu: Qemu, buf: &[u8], len: GuestReg| -> Result<(), QemuRWError> {
        unsafe {
            qemu.write_mem(input_addr, buf)?;

            // Start execution again at the snapshot PC.
            qemu.write_reg(Regs::Pc, snapshot_addr as GuestReg)?;
            qemu.write_reg(Regs::Sp, stack_ptr)?;
            qemu.write_return_address(ret_addr)?;

            // Typical function signature: (u8 *data, usize len).
            qemu.write_function_argument(0, input_addr)?;
            qemu.write_function_argument(1, len)?;

            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(_))) => {
                    // Ctrl‑C etc; exit cleanly.
                    process::exit(0);
                }
                Ok(other) => panic!("Unexpected QEMU exit: {other:?}"),
                Err(e) => panic!("QEMU run error: {e:?}"),
            }
        }

        Ok(())
    };

    // LibAFL state & fuzzer setup.
    let mut feedback = ();
    let mut objective = ();

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::new(),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Harness: copy the input into the mapped buffer and run from the snapshot.
    let mut harness =
        |emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut _, input: &BytesInput| {
            let qemu = emulator.qemu();

            let target = input.target_bytes();
            let mut buf = target.as_slice();
            let mut len = buf.len();
            if len > MAX_INPUT_SIZE {
                buf = &buf[0..MAX_INPUT_SIZE];
                len = MAX_INPUT_SIZE;
            }
            let len = len as GuestReg;

            reset(qemu, buf, len).unwrap();

            ExitKind::Ok
        };

    let mut executor = QemuExecutor::new(
        emulator,
        &mut harness,
        (),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        options.timeout,
    )
    .expect("Failed to create QemuExecutor");

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs_by_filenames(
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                &corpus_files
                    .into_iter()
                    .map(|e| e.path())
                    .collect::<Vec<PathBuf>>(),
            )
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &options.input_dir);
                process::exit(0);
            });
        info!("Imported {} inputs from disk.", state.corpus().count());
    }

    mgr.send_exiting()?;
    Err(Error::ShuttingDown)?
}
