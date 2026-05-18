use capstone::{
    arch::x86::X86OperandType, arch::BuildsCapstone, arch::DetailsArchInsn, Capstone, RegId,
};
use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{
        custom_filename::CustomFilenameToTestcaseFeedback, Feedback, MaxMapFeedback,
        StateInitializer, TimeFeedback,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, Input},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, HasSolutions, StdState},
};
use libafl_bolts::{
    ownedref::OwnedMutSlice, rands::StdRand, tuples::tuple_list, AsSlice, Error, Named,
};
use libafl_qemu::{
    capstone as qemu_capstone,
    command::{NopCommand, NopCommandManager},
    elf::EasyElf,
    modules::{
        calls::{CallTraceCollector, CallTracerModule, FullBacktraceCollector},
        edges::StdEdgeCoverageClassicModule,
        utils::{addr2line::AddressResolver, filters::StdAddressFilter},
        EmulatorModule, RedirectStdoutModule,
    },
    Emulator, GuestAddr, GuestUlong, Hook, NopEmulatorDriver, NopSnapshotManager, Qemu,
    QemuExitReason, QemuShutdownCause, Regs, SYS_exit, SYS_exit_group, SyscallHookResult,
    TargetSignalHandling,
};
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::BTreeMap,
    env, fmt, fs,
    io::Write,
    path::PathBuf,
    process,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_ALLOCATED_SIZE, MAX_EDGES_FOUND};

#[cfg(not(miri))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

static TARGET_LOC_COVERED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy)]
struct FunctionFrame {
    entry: Option<GuestAddr>,
    return_addr: GuestAddr,
    saw_target_hit: bool,
}

#[derive(Debug, Default)]
struct RuntimeTraceState {
    function_stack: Vec<FunctionFrame>,
    target_hits: usize,
    target_unknown_hits: usize,
    target_function_calls: BTreeMap<GuestAddr, usize>,
}

impl RuntimeTraceState {
    fn reset(&mut self, root_entry: GuestAddr) {
        self.function_stack.clear();
        self.function_stack.push(FunctionFrame {
            entry: Some(root_entry),
            return_addr: 0,
            saw_target_hit: false,
        });
        self.target_hits = 0;
        self.target_unknown_hits = 0;
        self.target_function_calls.clear();
    }

    fn on_call(&mut self, entry: Option<GuestAddr>, return_addr: GuestAddr) {
        self.function_stack.push(FunctionFrame {
            entry,
            return_addr,
            saw_target_hit: false,
        });
    }

    fn on_ret(&mut self, return_addr: GuestAddr) {
        while self.function_stack.len() > 1 {
            let frame = self.function_stack.pop().unwrap();
            if frame.return_addr == return_addr {
                break;
            }
        }
    }

    fn on_target_hit(&mut self) {
        self.target_hits += 1;
        if let Some(frame) = self.function_stack.last_mut() {
            if let Some(entry) = frame.entry {
                if !frame.saw_target_hit {
                    *self.target_function_calls.entry(entry).or_insert(0) += 1;
                    frame.saw_target_hit = true;
                }
            } else {
                self.target_unknown_hits += 1;
            }
        } else {
            self.target_unknown_hits += 1;
        }
    }
}

#[derive(Debug)]
struct TargetHitFeedback {
    name: Cow<'static, str>,
}

impl TargetHitFeedback {
    fn new() -> Self {
        Self {
            name: Cow::Borrowed("target_hit"),
        }
    }
}

impl Named for TargetHitFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> StateInitializer<S> for TargetHitFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for TargetHitFeedback {
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(TARGET_LOC_COVERED.load(Ordering::Relaxed))
    }
}

fn generate_reached_filename<S>(
    state: &mut S,
    _testcase: &mut Testcase<BytesInput>,
) -> Result<String, Error>
where
    S: HasSolutions<BytesInput>,
{
    let reached_id = state.solutions().count_all();
    let reached = true;
    let is_crash = false;
    Ok(format!("{reached_id}_{reached}_{is_crash}"))
}

std::thread_local! {
    static RUNTIME_TRACE_STATE: RefCell<RuntimeTraceState> =
        RefCell::new(RuntimeTraceState::default());
    static TARGET_EXEC_RANGE: RefCell<Option<(GuestAddr, GuestAddr)>> = RefCell::new(None);
}

fn record_target_hit() {
    RUNTIME_TRACE_STATE.with(|state| {
        state.borrow_mut().on_target_hit();
    });
}

fn set_target_exec_range(range: Option<(GuestAddr, GuestAddr)>) {
    TARGET_EXEC_RANGE.with(|state| {
        *state.borrow_mut() = range;
    });
}

fn target_exec_range() -> Option<(GuestAddr, GuestAddr)> {
    TARGET_EXEC_RANGE.with(|state| *state.borrow())
}

fn find_last_guest_frame(frames: &[GuestAddr]) -> Option<(usize, GuestAddr)> {
    let (range_start, range_end) = target_exec_range()?;

    frames.iter().enumerate().rev().find_map(|(idx, addr)| {
        ((*addr >= range_start) && (*addr < range_end)).then_some((idx, *addr))
    })
}

fn signal_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGILL => "SIGILL",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGTRAP => "SIGTRAP",
        _ => "UNKNOWN",
    }
}

fn shutdown_cause_detail(cause: &QemuShutdownCause) -> String {
    match cause {
        QemuShutdownCause::None => "no shutdown cause reported".to_string(),
        QemuShutdownCause::HostError => "host-side QEMU error".to_string(),
        QemuShutdownCause::HostQmpQuit => "QMP quit requested by host".to_string(),
        QemuShutdownCause::HostQmpSystemReset => "QMP system reset requested by host".to_string(),
        QemuShutdownCause::HostSignal(signal) => format!("host signal {signal:?}"),
        QemuShutdownCause::HostUi => "host UI requested shutdown".to_string(),
        QemuShutdownCause::GuestShutdown => "guest requested shutdown".to_string(),
        QemuShutdownCause::GuestReset => "guest requested reset".to_string(),
        QemuShutdownCause::GuestPanic => "guest panic".to_string(),
        QemuShutdownCause::SubsystemReset => "subsystem reset".to_string(),
        QemuShutdownCause::SnapshotLoad => "snapshot load completed".to_string(),
    }
}

fn suppress_guest_output(_: &[u8]) {}

struct RuntimeFunctionTracker {
    cs: Capstone,
}

impl RuntimeFunctionTracker {
    fn new() -> Self {
        Self {
            cs: qemu_capstone().detail(true).build().unwrap(),
        }
    }

    fn resolve_call_target(&self, pc: GuestAddr, call_len: usize) -> Option<GuestAddr> {
        let qemu = unsafe { Qemu::get_unchecked() };
        let mut bytes = [0_u8; 16];
        qemu.read_mem(pc, &mut bytes).ok()?;

        let insns = self.cs.disasm_count(&bytes, pc as u64, 1).ok()?;
        let insn = insns.first()?;
        let detail = self.cs.insn_detail(insn).ok()?;
        let arch_detail = detail.arch_detail();
        let x86_detail = arch_detail.x86()?;
        let operand = x86_detail.operands().next()?;

        match operand.op_type {
            X86OperandType::Imm(target) => Some(target as GuestAddr),
            X86OperandType::Reg(reg_id) => self.read_x86_reg(reg_id),
            X86OperandType::Mem(mem) => {
                let effective_addr = self.eval_x86_mem(pc, call_len, mem)?;
                self.read_pointer(effective_addr, operand.size)
            }
            X86OperandType::Invalid => None,
        }
    }

    fn read_pointer(&self, addr: GuestAddr, operand_size: u8) -> Option<GuestAddr> {
        let qemu = unsafe { Qemu::get_unchecked() };
        let pointer_size = match operand_size {
            0 => 8,
            2 | 4 | 8 => operand_size as usize,
            _ => return None,
        };

        let mut buf = [0_u8; 8];
        qemu.read_mem(addr, &mut buf[..pointer_size]).ok()?;

        Some(match pointer_size {
            2 => u16::from_le_bytes([buf[0], buf[1]]) as GuestAddr,
            4 => u32::from_le_bytes(buf[..4].try_into().unwrap()) as GuestAddr,
            8 => u64::from_le_bytes(buf) as GuestAddr,
            _ => unreachable!(),
        })
    }

    fn eval_x86_mem(
        &self,
        pc: GuestAddr,
        call_len: usize,
        mem: capstone::arch::x86::X86OpMem,
    ) -> Option<GuestAddr> {
        let base = self.eval_x86_base(pc, call_len, mem.base())?;
        let index = self.eval_x86_index(mem.index())?;
        let scale = i128::from(mem.scale());
        let disp = i128::from(mem.disp());

        let addr = (base as i128) + ((index as i128) * scale) + disp;
        if !(0..=(GuestAddr::MAX as i128)).contains(&addr) {
            return None;
        }

        Some(addr as GuestAddr)
    }

    fn eval_x86_base(&self, pc: GuestAddr, call_len: usize, reg_id: RegId) -> Option<GuestAddr> {
        if reg_id.0 == 0 {
            return Some(0);
        }

        match self.cs.reg_name(reg_id).as_deref() {
            Some("rip") => pc.checked_add(call_len as GuestAddr),
            _ => self.read_x86_reg(reg_id),
        }
    }

    fn eval_x86_index(&self, reg_id: RegId) -> Option<GuestAddr> {
        if reg_id.0 == 0 {
            return Some(0);
        }
        self.read_x86_reg(reg_id)
    }

    fn read_x86_reg(&self, reg_id: RegId) -> Option<GuestAddr> {
        let qemu = unsafe { Qemu::get_unchecked() };
        let reg_name = self.cs.reg_name(reg_id)?;
        let (reg, mask) = match reg_name.as_str() {
            "rax" => (Regs::Rax, u64::MAX),
            "eax" => (Regs::Rax, 0xffff_ffff),
            "rbx" => (Regs::Rbx, u64::MAX),
            "ebx" => (Regs::Rbx, 0xffff_ffff),
            "rcx" => (Regs::Rcx, u64::MAX),
            "ecx" => (Regs::Rcx, 0xffff_ffff),
            "rdx" => (Regs::Rdx, u64::MAX),
            "edx" => (Regs::Rdx, 0xffff_ffff),
            "rsi" => (Regs::Rsi, u64::MAX),
            "esi" => (Regs::Rsi, 0xffff_ffff),
            "rdi" => (Regs::Rdi, u64::MAX),
            "edi" => (Regs::Rdi, 0xffff_ffff),
            "rbp" => (Regs::Rbp, u64::MAX),
            "ebp" => (Regs::Rbp, 0xffff_ffff),
            "rsp" => (Regs::Rsp, u64::MAX),
            "esp" => (Regs::Rsp, 0xffff_ffff),
            "r8" => (Regs::R8, u64::MAX),
            "r8d" => (Regs::R8, 0xffff_ffff),
            "r9" => (Regs::R9, u64::MAX),
            "r9d" => (Regs::R9, 0xffff_ffff),
            "r10" => (Regs::R10, u64::MAX),
            "r10d" => (Regs::R10, 0xffff_ffff),
            "r11" => (Regs::R11, u64::MAX),
            "r11d" => (Regs::R11, 0xffff_ffff),
            "r12" => (Regs::R12, u64::MAX),
            "r12d" => (Regs::R12, 0xffff_ffff),
            "r13" => (Regs::R13, u64::MAX),
            "r13d" => (Regs::R13, 0xffff_ffff),
            "r14" => (Regs::R14, u64::MAX),
            "r14d" => (Regs::R14, 0xffff_ffff),
            "r15" => (Regs::R15, u64::MAX),
            "r15d" => (Regs::R15, 0xffff_ffff),
            _ => return None,
        };

        let value = qemu.read_reg(reg).ok()? as u64;
        Some((value & mask) as GuestAddr)
    }
}

impl fmt::Debug for RuntimeFunctionTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeFunctionTracker")
            .finish_non_exhaustive()
    }
}

impl CallTraceCollector for RuntimeFunctionTracker {
    fn on_call<ET, I, S>(
        &mut self,
        _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        pc: GuestAddr,
        call_len: usize,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
        let return_addr = pc.saturating_add(call_len as GuestAddr);
        let callee_entry = self.resolve_call_target(pc, call_len);
        RUNTIME_TRACE_STATE.with(|state| {
            state.borrow_mut().on_call(callee_entry, return_addr);
        });
    }

    fn on_ret<ET, I, S>(
        &mut self,
        _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
        _state: Option<&mut S>,
        _pc: GuestAddr,
        ret_addr: GuestAddr,
    ) where
        ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
        I: Unpin,
        S: Unpin,
    {
        RUNTIME_TRACE_STATE.with(|state| {
            state.borrow_mut().on_ret(ret_addr);
        });
    }

    fn pre_exec<I>(&mut self, _qemu: Qemu, _input: &I)
    where
        I: Input,
    {
        TARGET_LOC_COVERED.store(false, Ordering::Relaxed);
        let root_entry = _qemu.read_reg(Regs::Pc).ok().map(|pc| pc as GuestAddr);
        RUNTIME_TRACE_STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.function_stack.clear();
            if let Some(root_entry) = root_entry {
                state.reset(root_entry);
            } else {
                state.target_hits = 0;
                state.target_unknown_hits = 0;
                state.target_function_calls.clear();
            }
        });
    }
}

#[derive(Debug, Default)]
struct StackTracePrinter {}

fn on_target_loc_covered<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _pc: GuestAddr,
) where
    ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    TARGET_LOC_COVERED.store(true, Ordering::Relaxed);
    record_target_hit();
}

#[expect(clippy::too_many_arguments)]
fn on_target_exit_syscall<ET, I, S>(
    qemu: Qemu,
    _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    syscall: i32,
    _arg0: GuestUlong,
    _arg1: GuestUlong,
    _arg2: GuestUlong,
    _arg3: GuestUlong,
    _arg4: GuestUlong,
    _arg5: GuestUlong,
    _arg6: GuestUlong,
    _arg7: GuestUlong,
) -> SyscallHookResult
where
    ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    if syscall == SYS_exit as i32 || syscall == SYS_exit_group as i32 {
        if let Some(cpu) = qemu.current_cpu() {
            cpu.trigger_breakpoint();
            return SyscallHookResult::Skip(0);
        }
    }

    SyscallHookResult::Run
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
    sig: i32,
) where
    ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let reason = format!("crash (signal {sig} {})", signal_name(sig));
    log::info!("[crash] [signal {sig}] [name {}]", signal_name(sig));
    dump_stacktrace(qemu, &reason);
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
        if let Some((idx, addr)) = find_last_guest_frame(&frames) {
            eprintln!(
                "\t[fault-addr] [idx {idx}] [addr {addr:#x}] [symbol {}]",
                resolver.resolve(addr)
            );
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
        emulator_modules.pre_syscalls(Hook::Function(on_target_exit_syscall::<ET, I, S>));
    }

    unsafe fn on_timeout(&mut self) {
        dump_stacktrace(Qemu::get_unchecked(), "timeout");
    }
}

#[derive(Parser, Debug)]
#[clap(about)]
#[command(
    name = "qemu_targeted_simple",
    about = "A simple qemu-usermode fuzzer that collects target-hit inputs"
)]
struct Opts {
    #[arg(short, long, default_value = "0", value_parser = parse_guest_addr)]
    target_loc: usize,
    #[arg(short, long)]
    input: PathBuf,
    #[arg(short, long)]
    output: PathBuf,

    binary: PathBuf,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
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
            writeln!(buf, "{} [time {}]", record.args(), elapsed)
        })
        .init();

    log::info!("Starting qemu_targeted_simple");

    let opts = Opts::parse();
    let binary = opts.binary;
    let input = opts.input;
    let output = opts.output;
    let seeds_dir = output.join("seeds");
    let reached_dir = output.join("reached");

    fs::create_dir_all(&seeds_dir)?;
    fs::create_dir_all(&reached_dir)?;

    let seed_copy_path = seeds_dir.join("seed_0");
    if input != seed_copy_path {
        fs::copy(&input, &seed_copy_path)?;
    }

    let runtime_input_path = input.clone();
    let runtime_input_path_str = runtime_input_path.to_string_lossy().into_owned();
    let initial_input = BytesInput::new(fs::read(&input)?);

    let mut elf_buf = Vec::new();
    let elf = EasyElf::from_file(&binary, &mut elf_buf)?;

    let mut qemu_args = Vec::with_capacity(2 + opts.target_args.len());
    qemu_args.push(env::args().next().unwrap());
    qemu_args.push(binary.to_string_lossy().into_owned());
    qemu_args.extend(opts.target_args.into_iter().map(|arg| {
        if arg == "@@" {
            runtime_input_path_str.clone()
        } else {
            arg
        }
    }));

    let full_backtrace = unsafe { FullBacktraceCollector::new() };
    let runtime_function_tracker = RuntimeFunctionTracker::new();
    let redirect_stdout = RedirectStdoutModule::new()
        .with_stdout(suppress_guest_output)
        .with_stderr(suppress_guest_output);

    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_ALLOCATED_SIZE),
            &raw mut MAX_EDGES_FOUND,
        ))
        .track_indices()
    };

    let modules = tuple_list!(
        redirect_stdout,
        StdEdgeCoverageClassicModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()?,
        CallTracerModule::new(
            StdAddressFilter::default(),
            tuple_list!(full_backtrace, runtime_function_tracker)
        ),
        StackTracePrinter {},
    );

    let time_observer = TimeObserver::new("time");
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer)
    );
    let mut objective = feedback_or_fast!(
        CustomFilenameToTestcaseFeedback::new(generate_reached_filename::<State>),
        TargetHitFeedback::new()
    );

    let mut state = StdState::new(
        StdRand::new(),
        InMemoryOnDiskCorpus::<BytesInput>::new(seeds_dir.clone())?,
        OnDiskCorpus::<BytesInput>::new(reached_dir.clone())?,
        &mut feedback,
        &mut objective,
    )?;

    type State =
        StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut emulator: Emulator<
        NopCommand,
        NopCommandManager,
        NopEmulatorDriver,
        _,
        BytesInput,
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
    log::info!("[entry] [address {entry:#x}]");

    let entry_addr = entry as GuestAddr;
    let target_exec_range = qemu.mappings().find_map(|map| {
        let start = map.start() as GuestAddr;
        let end = map.end() as GuestAddr;
        (start <= entry_addr && entry_addr < end).then_some((start, end))
    });
    set_target_exec_range(target_exec_range);

    let target_loc = opts.target_loc;
    let target_loc_runtime: Option<usize> = if target_loc != 0 {
        if elf.is_pic() {
            Some(load_addr + target_loc)
        } else {
            Some(target_loc)
        }
    } else {
        None
    };
    match target_loc_runtime {
        Some(addr) => log::info!("[target-info] [set true] [location {addr:#x}]"),
        None => log::info!("[target-info] [set false] [location 0]"),
    }

    TARGET_LOC_COVERED.store(false, Ordering::Relaxed);
    if let Some(addr) = target_loc_runtime {
        emulator.modules_mut().instruction_function(
            addr,
            on_target_loc_covered::<_, BytesInput, State>,
            true,
        );
    }

    emulator.set_target_crash_handling(&TargetSignalHandling::ReturnToHarness);

    let monitor = SimpleMonitor::new(|s| log::info!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    let runtime_input_path_for_harness = output.join(".cur_input");
    let mut harness = move |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                            _state: &mut State,
                            input: &BytesInput|
          -> ExitKind {
        let target = input.target_bytes();
        fs::write(&runtime_input_path_for_harness, target.as_slice())
            .expect("failed to update runtime input file");

        let qemu = emulator.qemu();
        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Crash) => ExitKind::Crash,
                Ok(QemuExitReason::Timeout) => ExitKind::Timeout,
                Ok(QemuExitReason::SyncExit) => ExitKind::Ok,
                Ok(QemuExitReason::End(reason)) => {
                    log::debug!("[qemu-end] [detail {}]", shutdown_cause_detail(&reason));
                    ExitKind::Ok
                }
                Ok(QemuExitReason::Breakpoint(reason)) => {
                    log::debug!("[qemu-breakpoint] [addr {reason:#x}]");
                    ExitKind::Ok
                }
                Err(err) => {
                    log::debug!("[qemu-error] [detail {:?}]", err);
                    ExitKind::Crash
                }
            }
        }
    };

    let timeout = std::time::Duration::from_millis(1000);
    let mut executor = libafl_qemu::executor::QemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    state.corpus_mut().add(Testcase::new(initial_input))?;
    log::info!("Seeded corpus from {}", input.display());

    let mut stages = tuple_list!(StdMutationalStage::new(HavocScheduledMutator::new(
        havoc_mutations()
    )),);

    log::info!(
        "running {} with seed {}",
        binary.display(),
        seed_copy_path.display()
    );

    match fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr) {
        Ok(()) | Err(Error::ShuttingDown) => Ok(()),
        Err(err) => Err(err.into()),
    }
}
