use clap::Parser;
use libafl::{
    corpus::InMemoryCorpus,
    events::SimpleEventManager,
    executors::{Executor, ExitKind},
    feedbacks::CrashFeedback,
    fuzzer::StdFuzzer,
    inputs::NopInput,
    monitors::SimpleMonitor,
    schedulers::QueueScheduler,
    state::StdState,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list, Error};
use libafl_qemu::{
    command::{NopCommand, NopCommandManager},
    elf::EasyElf,
    modules::{
        calls::{CallTracerModule, FullBacktraceCollector},
        utils::{addr2line::AddressResolver, filters::StdAddressFilter},
        EmulatorModule, SnapshotModule,
    },
    Emulator, GuestAddr, NopEmulatorDriver, NopSnapshotManager, Qemu, QemuExitReason,
    TargetSignalHandling,
};
use std::{
    env,
    io::Write,
    path::PathBuf,
    process,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

#[cfg(not(miri))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

static PATCH_LOC_COVERED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Default)]
struct StackTracePrinter;

fn on_patch_loc_covered<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _pc: GuestAddr,
) where
    ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    PATCH_LOC_COVERED.store(true, Ordering::Relaxed);
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

fn on_crash_stacktrace<ET, I, S>(
    qemu: Qemu,
    _modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    _sig: i32,
) where
    ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    dump_stacktrace(qemu, "crash");
    if let Some(cpu) = qemu.current_cpu() {
        eprint!("QEMU Context:\n{}", cpu.display_context());
    }
}

fn dump_stacktrace(qemu: Qemu, reason: &str) {
    eprintln!("stacktrace on {reason}:");
    let resolver = AddressResolver::new(&qemu);
    if let Some(frames) = FullBacktraceCollector::backtrace() {
        for (idx, addr) in frames.iter().rev().enumerate() {
            eprintln!("\t#{idx} {addr:#x}{}", resolver.resolve(*addr));
        }
    } else {
        eprintln!("\t(no stack collected)");
    }
}

impl<I, S> EmulatorModule<I, S> for StackTracePrinter
where
    I: Unpin,
    S: Unpin,
{
    fn post_qemu_init<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        emulator_modules.crash_function(on_crash_stacktrace::<ET, I, S>);
    }

    unsafe fn on_timeout(&mut self) {
        dump_stacktrace(Qemu::get_unchecked(), "timeout");
    }
}

#[derive(Parser, Debug)]
#[clap(about)]
#[command(
    name = "qemu_stacktrace",
    about = "A simple qemu-usermode runner that prints a stacktrace on crash or timeout"
)]
struct Opts {
    #[arg(short, long, default_value = "0", value_parser = parse_guest_addr)]
    patch_loc: usize,

    binary: PathBuf,
    #[arg(trailing_var_arg = true)]
    target_args: Vec<String>,
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
    let start_time = Instant::now();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(move |buf, record| {
            let elapsed = start_time.elapsed().as_millis();
            writeln!(buf, "{}ms {}", elapsed, record.args())
        })
        .init();

    log::info!("Starting qemu_stacktrace");

    let opts = Opts::parse();
    let binary = opts.binary;
    let mut elf_buf = Vec::new();
    let elf = EasyElf::from_file(&binary, &mut elf_buf)?;

    let full_backtrace = unsafe { FullBacktraceCollector::new() };
    let modules = tuple_list!(
        SnapshotModule::new(),
        CallTracerModule::new(StdAddressFilter::default(), tuple_list!(full_backtrace)),
        StackTracePrinter::default(),
    );

    let mut qemu_args = Vec::with_capacity(2 + opts.target_args.len());
    qemu_args.push(env::args().next().unwrap());
    qemu_args.push(binary.to_string_lossy().into_owned());
    qemu_args.extend(opts.target_args);

    let mut feedback = CrashFeedback::new();
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::<NopInput>::new(),
        InMemoryCorpus::<NopInput>::new(),
        &mut feedback,
        &mut objective,
    )?;
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let monitor = SimpleMonitor::new(|s| log::info!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    type State = StdState<InMemoryCorpus<NopInput>, NopInput, StdRand, InMemoryCorpus<NopInput>>;

    let mut emulator: Emulator<
        NopCommand,
        NopCommandManager,
        NopEmulatorDriver,
        _,
        NopInput,
        State,
        NopSnapshotManager,
    > = Emulator::empty()
        .qemu_parameters(qemu_args)
        .modules(modules)
        .build()?;

    let qemu = emulator.qemu();
    let load_addr = qemu.load_addr();
    let entry = elf
        .entry_point(if elf.is_pic() { load_addr } else { 0 })
        .ok_or_else(|| {
            Box::new(Error::illegal_argument(format!(
                "could not determine ELF entry point for {}",
                binary.display()
            ))) as Box<dyn std::error::Error>
        })?;
    log::info!("entry point: {entry:#x}");

    let patch_loc = opts.patch_loc;
    let patch_loc_runtime: Option<usize> = if patch_loc != 0 {
        if elf.is_pic() {
            Some(load_addr + patch_loc)
        } else {
            Some(patch_loc)
        }
    } else {
        None
    };
    match patch_loc_runtime {
        Some(addr) => log::info!("[patch-info] [set true] [location {addr:#x}]"),
        None => log::info!("[patch-info] [set false] [location 0]"),
    }

    PATCH_LOC_COVERED.store(false, Ordering::Relaxed);
    if let Some(addr) = patch_loc_runtime {
        emulator.modules_mut().instruction_function(
            addr,
            on_patch_loc_covered::<_, NopInput, State>,
            true,
        );
    }
    qemu.entry_break(entry);
    emulator.modules_mut().first_exec_all(qemu, &mut state);
    emulator.set_target_crash_handling(&TargetSignalHandling::ReturnToHarness);

    log::info!("running {} @ {entry:#x}", binary.display());

    let harness = move |_emulator: &mut Emulator<_, _, _, _, _, _, _>,
                        _state: &mut State,
                        _input: &NopInput|
          -> ExitKind {
        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Crash) => ExitKind::Crash,
                Ok(QemuExitReason::Timeout) => ExitKind::Timeout,
                Ok(QemuExitReason::SyncExit) => ExitKind::Ok,
                Ok(QemuExitReason::End(_)) => ExitKind::Ok,
                Ok(QemuExitReason::Breakpoint(_)) => ExitKind::Ok,
                Err(_) => ExitKind::Crash,
            }
        }
    };

    let timeout = std::time::Duration::from_secs(30);
    let mut executor = libafl_qemu::QemuExecutor::new(
        emulator,
        harness,
        (),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    let input = NopInput::new();
    let result = executor.run_target(&mut fuzzer, &mut state, &mut mgr, &input);

    let resolver = AddressResolver::new(&qemu);

    match &result {
        Ok(ExitKind::Crash) => log::info!("result: crash"),
        Ok(ExitKind::Ok) => log::info!("result: exit"),
        Ok(other) => log::info!("result: {other:?}"),
        Err(err) => log::info!("result: error: {err:?}"),
    }

    if matches!(result, Ok(ExitKind::Crash)) {
        log::info!("stacktrace:");
        if let Some(frames) = FullBacktraceCollector::backtrace() {
            for (idx, addr) in frames.iter().rev().enumerate() {
                log::info!(
                    "[stacktrace] [idx {idx}] [addr {addr:#x}] [symbol {}]",
                    resolver.resolve(*addr)
                );
            }
        } else {
            log::info!("[error] no stack collected");
        }
    }

    if let Some(addr) = patch_loc_runtime {
        log::info!(
            "[patch-cov] [location {addr:#x}] [covered {}]",
            PATCH_LOC_COVERED.load(Ordering::Relaxed)
        );
    }

    Ok(())
}
