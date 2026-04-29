use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use clap::Parser;
use libafl::{
    corpus::{InMemoryCorpus, NopCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, Executor},
    feedbacks::CrashFeedback,
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    schedulers::QueueScheduler,
    state::StdState,
};
use libafl_bolts::{
    os::unix_signals::Signal,
    rands::StdRand,
    tuples::tuple_list,
    AsSlice,
    Error,
};
use libafl_qemu::{
    ArchExtras, Emulator, GuestAddr, GuestReg, MmapPerms, QemuExitError, QemuExitReason,
    QemuExecutor, QemuShutdownCause, Regs,
    modules::SnapshotModule,
};

#[cfg(not(miri))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Clone)]
struct CaseResult {
    exit_kind: ExitKind,
    patch_hit: bool,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Lightweight binary-only differential tester for libafl_qemu user mode", long_about = None)]
struct Opts {
    /// Path to the original binary
    #[arg(long)]
    original: PathBuf,

    /// Path to the patched binary
    #[arg(long)]
    patched: PathBuf,

    /// Runtime address of the target function entry
    #[arg(long, value_parser = parse_guest_addr)]
    entry: GuestAddr,

    /// Runtime address of the patch site / trampoline entry
    #[arg(long, value_parser = parse_guest_addr)]
    patch: GuestAddr,

    /// Input file or directory of inputs
    #[arg(long)]
    input: PathBuf,

    /// Maximum number of bytes copied into the guest input buffer
    #[arg(long, default_value_t = 0x1000)]
    max_input_size: usize,

    /// Timeout in milliseconds for a single execution
    #[arg(long, default_value_t = 5_000)]
    timeout_ms: u64,

    /// Extra target arguments forwarded to both binaries. Use @@ as the input placeholder.
    /// If @@ is omitted, the target is expected to read from stdin.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    target_args: Vec<String>,
}

fn parse_guest_addr(value: &str) -> Result<GuestAddr, String> {
    let trimmed = value.trim();
    let parsed = if let Some(hex) = trimmed.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else if let Some(hex) = trimmed.strip_prefix("0X") {
        u64::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u64>()
    };

    parsed
        .map(|addr| addr as GuestAddr)
        .map_err(|err| format!("invalid guest address '{value}': {err}"))
}

fn main() {
    #[cfg(target_os = "linux")]
    {
        if let Err(err) = run() {
            eprintln!("error: {err}");
            process::exit(1);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        panic!("qemu-user and libafl_qemu is only supported on linux!");
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env_logger::try_init().is_err() {
        // logger already initialized
    }

    let opts = Opts::parse();
    let inputs = collect_inputs(&opts.input)?;

    if inputs.is_empty() {
        return Err(Box::new(Error::illegal_argument(
            "no input files were found",
        )));
    }

    let mut original = build_runner("original", &opts.original, &opts)?;
    let mut patched = build_runner("patched", &opts.patched, &opts)?;

    for input_path in inputs {
        let data = fs::read(&input_path)?;
        let original_result = original(&data)?;
        let patched_result = patched(&data)?;

        let diff = original_result.exit_kind != patched_result.exit_kind
            || original_result.patch_hit != patched_result.patch_hit;

        println!(
            "{:<40} | orig: {:<5} hit={} | patched: {:<5} hit={} | {}",
            input_path.display(),
            format_exit_kind(original_result.exit_kind),
            original_result.patch_hit,
            format_exit_kind(patched_result.exit_kind),
            patched_result.patch_hit,
            if diff { "DIFF" } else { "same" }
        );
    }

    Ok(())
}

fn collect_inputs(path: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut inputs = Vec::new();

    if path.is_file() {
        inputs.push(path.to_path_buf());
    } else if path.is_dir() {
        collect_inputs_recursively(path, &mut inputs)?;
        inputs.sort();
    } else {
        return Err(Box::new(Error::illegal_argument(format!(
            "input path does not exist: {}",
            path.display()
        ))));
    }

    Ok(inputs)
}

fn collect_inputs_recursively(
    path: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_inputs_recursively(&entry_path, out)?;
        } else if entry_path.is_file() {
            out.push(entry_path);
        }
    }

    Ok(())
}

fn format_exit_kind(kind: ExitKind) -> &'static str {
    match kind {
        ExitKind::Ok => "ok",
        ExitKind::Crash => "crash",
        ExitKind::Oom => "oom",
        ExitKind::Timeout => "timeout",
        ExitKind::Diff { .. } => "diff",
    }
}

type Runner = Box<dyn FnMut(&[u8]) -> Result<CaseResult, Error>>;

fn build_runner(
    label: &'static str,
    binary: &Path,
    opts: &Opts,
) -> Result<Runner, Error> {
    let entry = opts.entry;
    let patch = opts.patch;
    let max_input_size = opts.max_input_size;
    let target_args = opts
        .target_args
        .iter()
        .filter(|arg| arg.as_str() != "@@")
        .cloned()
        .collect::<Vec<_>>();

    let mut feedback = CrashFeedback::new();
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::<BytesInput>::new(),
        NopCorpus::<BytesInput>::new(),
        &mut feedback,
        &mut objective,
    )?;

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let monitor = SimpleMonitor::new(move |s| log::info!("[{label}] {s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    let mut qemu_args = Vec::with_capacity(1 + target_args.len());
    qemu_args.push(binary.as_os_str().to_string_lossy().into_owned());
    qemu_args.extend(target_args);

    let emulator = Emulator::empty()
        .qemu_parameters(qemu_args)
        .modules(tuple_list!(SnapshotModule::new(),))
        .build()?;

    let qemu = emulator.qemu();
    qemu.entry_break(entry);

    let stack_ptr = qemu
        .read_reg(Regs::Sp)
        .map_err(|err| Error::illegal_state(format!("failed to read stack pointer: {err:?}")))?;
    let return_addr = qemu
        .read_return_address()
        .map_err(|err| Error::illegal_state(format!("failed to read return address: {err:?}")))?;
    let input_addr = qemu
        .map_private(0, max_input_size, MmapPerms::ReadWrite)
        .map_err(|err| Error::illegal_state(format!("failed to map input buffer: {err:?}")))?;
    qemu.set_breakpoint(patch);

    let patch_hit = Arc::new(AtomicBool::new(false));
    let inner_patch_hit = Arc::clone(&patch_hit);

    let harness = move |_emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut _, input: &BytesInput| {
        let target = input.target_bytes();
        let bytes = target.as_slice();
        let len = bytes.len().min(max_input_size);

        inner_patch_hit.store(false, Ordering::Relaxed);

        unsafe {
            qemu.write_mem(input_addr, &bytes[..len]).expect("qemu write failed");
            qemu.write_reg(Regs::Pc, entry as GuestReg).expect("write pc failed");
            qemu.write_reg(Regs::Sp, stack_ptr as GuestReg).expect("write sp failed");
            qemu.write_return_address(return_addr)
                .expect("write return address failed");
            qemu.write_function_argument(0, input_addr as GuestReg)
                .expect("write arg0 failed");
            qemu.write_function_argument(1, len as GuestReg)
                .expect("write arg1 failed");

            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {
                    inner_patch_hit.store(true, Ordering::Relaxed);
                    ExitKind::Ok
                }
                Ok(QemuExitReason::Crash) => ExitKind::Crash,
                Ok(QemuExitReason::Timeout) => ExitKind::Timeout,
                Ok(QemuExitReason::SyncExit) => ExitKind::Ok,
                Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(Signal::SigInterrupt))) => {
                    process::exit(libafl_bolts::os::CTRL_C_EXIT)
                }
                Ok(QemuExitReason::End(_)) => ExitKind::Ok,
                Err(QemuExitError::UnexpectedExit) => ExitKind::Crash,
                Err(QemuExitError::UnknownKind) => ExitKind::Crash,
            }
        }
    };

    let timeout = Duration::from_millis(opts.timeout_ms);
    let mut executor = QemuExecutor::new(
        emulator,
        harness,
        (),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    let runner = move |bytes: &[u8]| -> Result<CaseResult, Error> {
        patch_hit.store(false, Ordering::Relaxed);
        let input = BytesInput::new(bytes.to_vec());
        let exit_kind = executor.run_target(&mut fuzzer, &mut state, &mut mgr, &input)?;

        Ok(CaseResult {
            exit_kind,
            patch_hit: patch_hit.load(Ordering::Relaxed),
        })
    };

    Ok(Box::new(runner))
}
