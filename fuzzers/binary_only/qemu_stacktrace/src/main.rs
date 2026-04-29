use std::{env, path::PathBuf, process};
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
    elf::EasyElf,
    command::{NopCommand, NopCommandManager},
    modules::{
        calls::{CallTracerModule, FullBacktraceCollector},
        EmulatorModule,
        utils::{addr2line::AddressResolver, filters::StdAddressFilter},
        SnapshotModule,
    },
    Emulator, NopEmulatorDriver, NopSnapshotManager, Qemu, QemuExitReason, TargetSignalHandling,
};

#[cfg(not(miri))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Default)]
struct StackTracePrinter;

fn on_crash_stacktrace<ET, I, S>(
    qemu: Qemu,
    _modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    _sig: i32,
)
where
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
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>)
    where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    {
        emulator_modules.crash_function(on_crash_stacktrace::<ET, I, S>);
    }

    unsafe fn on_timeout(&mut self) {
        dump_stacktrace(Qemu::get_unchecked(), "timeout");
    }
}

#[derive(Debug)]
struct Opts {
    binary: PathBuf,

    target_args: Vec<String>,
}

impl Opts {
    fn parse() -> Result<Self, Box<dyn std::error::Error>> {
        let mut args = env::args_os().skip(1);
        let binary = args
            .next()
            .ok_or_else(|| Error::illegal_argument("usage: qemu_stacktrace <binary> [args...]") as Error)?;

        let target_args = args
            .map(|arg| {
                arg.into_string().map_err(|_| {
                    Error::illegal_argument("target arguments must be valid UTF-8")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            binary: PathBuf::from(binary),
            target_args,
        })
    }
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
        // already initialized
    }

    log::info!("Starting qemu_stacktrace");

    let opts = Opts::parse()?;
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
    let entry = elf.entry_point(if elf.is_pic() { load_addr } else { 0 }).ok_or_else(|| {
        Box::new(Error::illegal_argument(format!(
            "could not determine ELF entry point for {}",
            binary.display()
        ))) as Box<dyn std::error::Error>
    })?;

    log::info!("entry point: {entry:#x}");
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
                log::info!("\t#{idx} {addr:#x}{}", resolver.resolve(*addr));
            }
        } else {
            log::info!("\t(no stack collected)");
        }
    }

    Ok(())
}
