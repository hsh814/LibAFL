use capstone::{
    arch::x86::X86OperandType, arch::BuildsCapstone, arch::DetailsArchInsn, Capstone, RegId,
};
use clap::Parser;
use libafl::{
    corpus::InMemoryCorpus,
    executors::ExitKind,
    feedbacks::CrashFeedback,
    inputs::{Input, NopInput},
    state::StdState,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list, Error};
use libafl_qemu::{
    capstone as qemu_capstone,
    command::{NopCommand, NopCommandManager},
    elf::EasyElf,
    modules::{
        calls::{CallTraceCollector, CallTracerModule, FullBacktraceCollector},
        utils::{addr2line::AddressResolver, filters::StdAddressFilter},
        EmulatorModule, RedirectStdoutModule,
    },
    Emulator, GuestAddr, GuestUlong, GuestUsize, Hook, NopEmulatorDriver, NopSnapshotManager, Qemu,
    QemuExitReason, QemuShutdownCause, Regs, SYS_exit, SYS_exit_group, SyscallHookResult,
    TargetSignalHandling,
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    env, fmt,
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

#[derive(Debug, Clone, Copy)]
struct FunctionFrame {
    entry: Option<GuestAddr>,
    return_addr: GuestAddr,
    saw_patch_hit: bool,
}

#[derive(Debug, Default)]
struct RuntimeTraceState {
    function_stack: Vec<FunctionFrame>,
    visited_basic_blocks: BTreeMap<GuestAddr, usize>,
    patch_hits: usize,
    patch_unknown_hits: usize,
    patch_function_calls: BTreeMap<GuestAddr, usize>,
}

impl RuntimeTraceState {
    fn reset(&mut self, root_entry: GuestAddr) {
        self.function_stack.clear();
        self.function_stack.push(FunctionFrame {
            entry: Some(root_entry),
            return_addr: 0,
            saw_patch_hit: false,
        });
        self.visited_basic_blocks.clear();
        self.patch_hits = 0;
        self.patch_unknown_hits = 0;
        self.patch_function_calls.clear();
    }

    fn on_basic_block_hit(&mut self, addr: GuestAddr) {
        *self.visited_basic_blocks.entry(addr).or_insert(0) += 1;
    }

    fn on_call(&mut self, entry: Option<GuestAddr>, return_addr: GuestAddr) {
        self.function_stack.push(FunctionFrame {
            entry,
            return_addr,
            saw_patch_hit: false,
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

    fn on_patch_hit(&mut self) {
        self.patch_hits += 1;
        if let Some(frame) = self.function_stack.last_mut() {
            if let Some(entry) = frame.entry {
                if !frame.saw_patch_hit {
                    *self.patch_function_calls.entry(entry).or_insert(0) += 1;
                    frame.saw_patch_hit = true;
                }
            } else {
                self.patch_unknown_hits += 1;
            }
        } else {
            self.patch_unknown_hits += 1;
        }
    }

    fn patch_summary(&self) -> PatchSummary {
        PatchSummary {
            hits: self.patch_hits,
            unknown_hits: self.patch_unknown_hits,
            function_call_entries: self
                .patch_function_calls
                .iter()
                .map(|(addr, calls)| (*addr, *calls))
                .collect(),
        }
    }

    fn basic_block_summary(&self) -> Vec<(GuestAddr, usize)> {
        self.visited_basic_blocks
            .iter()
            .map(|(addr, hits)| (*addr, *hits))
            .collect()
    }
}

#[derive(Debug, Default, Clone)]
struct PatchSummary {
    hits: usize,
    unknown_hits: usize,
    function_call_entries: Vec<(GuestAddr, usize)>,
}

std::thread_local! {
    static RUNTIME_TRACE_STATE: RefCell<RuntimeTraceState> =
        RefCell::new(RuntimeTraceState::default());
    static TARGET_EXEC_RANGE: RefCell<Option<(GuestAddr, GuestAddr)>> = RefCell::new(None);
}

fn record_patch_hit() {
    RUNTIME_TRACE_STATE.with(|state| {
        state.borrow_mut().on_patch_hit();
    });
}

fn patch_summary() -> PatchSummary {
    RUNTIME_TRACE_STATE.with(|state| state.borrow().patch_summary())
}

fn basic_block_summary() -> Vec<(GuestAddr, usize)> {
    RUNTIME_TRACE_STATE.with(|state| state.borrow().basic_block_summary())
}

fn set_target_exec_range(range: Option<(GuestAddr, GuestAddr)>) {
    TARGET_EXEC_RANGE.with(|state| {
        *state.borrow_mut() = range;
    });
}

fn target_exec_range() -> Option<(GuestAddr, GuestAddr)> {
    TARGET_EXEC_RANGE.with(|state| *state.borrow())
}

fn record_basic_block_hit(addr: GuestAddr) {
    RUNTIME_TRACE_STATE.with(|state| {
        state.borrow_mut().on_basic_block_hit(addr);
    });
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
        let root_entry = _qemu.read_reg(Regs::Pc).ok().map(|pc| pc as GuestAddr);
        RUNTIME_TRACE_STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.function_stack.clear();
            if let Some(root_entry) = root_entry {
                state.reset(root_entry);
            } else {
                state.visited_basic_blocks.clear();
                state.patch_hits = 0;
                state.patch_unknown_hits = 0;
                state.patch_function_calls.clear();
            }
        });
    }
}

#[derive(Debug, Default)]
struct StackTracePrinter {
    trace_basic_blocks: bool,
}

fn on_basic_block_generated<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    Some(pc as u64)
}

fn on_basic_block_post_generated<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _pc: GuestAddr,
    _block_length: GuestUsize,
) where
    ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
}

fn on_basic_block_executed<ET, I, S>(
    _qemu: Qemu,
    _emulator_modules: &mut libafl_qemu::EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    id: u64,
) where
    ET: libafl_qemu::modules::EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    record_basic_block_hit(id as GuestAddr);
}

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
    record_patch_hit();
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
        if self.trace_basic_blocks {
            emulator_modules.hooks_mut().blocks(
                Hook::Function(on_basic_block_generated::<ET, I, S>),
                Hook::Function(on_basic_block_post_generated::<ET, I, S>),
                Hook::Function(on_basic_block_executed::<ET, I, S>),
            );
        }
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
    name = "qemu_stacktrace",
    about = "A simple qemu-usermode runner that prints a stacktrace on crash or timeout"
)]
struct Opts {
    #[arg(short, long, default_value = "0", value_parser = parse_guest_addr)]
    patch_loc: usize,
    #[arg(long)]
    trace_basic_blocks: bool,
    #[arg(short, long)]
    input: PathBuf,

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

    log::info!("Starting qemu_stacktrace");

    let opts = Opts::parse();
    let binary = opts.binary;
    let input = opts.input;
    let mut elf_buf = Vec::new();
    let elf = EasyElf::from_file(&binary, &mut elf_buf)?;

    let full_backtrace = unsafe { FullBacktraceCollector::new() };
    let runtime_function_tracker = RuntimeFunctionTracker::new();
    let redirect_stdout = RedirectStdoutModule::new()
        .with_stdout(suppress_guest_output)
        .with_stderr(suppress_guest_output);
    let modules = tuple_list!(
        redirect_stdout,
        CallTracerModule::new(
            StdAddressFilter::default(),
            tuple_list!(full_backtrace, runtime_function_tracker)
        ),
        StackTracePrinter {
            trace_basic_blocks: opts.trace_basic_blocks,
        },
    );

    let input_path = input.to_string_lossy().into_owned();
    let mut qemu_args = Vec::with_capacity(2 + opts.target_args.len());
    qemu_args.push(env::args().next().unwrap());
    qemu_args.push(binary.to_string_lossy().into_owned());
    qemu_args.extend(opts.target_args.into_iter().map(|arg| {
        if arg == "@@" {
            input_path.clone()
        } else {
            arg
        }
    }));

    let mut feedback = CrashFeedback::new();
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::<NopInput>::new(),
        InMemoryCorpus::<NopInput>::new(),
        &mut feedback,
        &mut objective,
    )?;

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
    log::info!("[entry] [address {entry:#x}]");

    let entry_addr = entry as GuestAddr;
    let target_exec_range = qemu.mappings().find_map(|map| {
        let start = map.start() as GuestAddr;
        let end = map.end() as GuestAddr;
        (start <= entry_addr && entry_addr < end).then_some((start, end))
    });
    set_target_exec_range(target_exec_range);

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
    emulator.first_exec(&mut state);
    emulator.set_target_crash_handling(&TargetSignalHandling::ReturnToHarness);

    log::info!("running {} @ {entry:#x}", binary.display());

    let input = NopInput::new();
    emulator.pre_exec(&mut state, &input);
    let qemu_exit = unsafe { qemu.run() };
    log::info!("exit-raw {:?}", qemu_exit);

    let mut exit_kind = match qemu_exit {
        Ok(QemuExitReason::Crash) => {
            log::info!("[qemu-exit] [kind crash] [detail target crash]");
            ExitKind::Crash
        }
        Ok(QemuExitReason::Timeout) => {
            log::info!("[qemu-exit] [kind timeout] [detail execution timed out]");
            ExitKind::Timeout
        }
        Ok(QemuExitReason::SyncExit) => {
            log::info!("[qemu-exit] [kind sync exit] [detail guest requested synchronous exit]");
            ExitKind::Ok
        }
        Ok(QemuExitReason::End(reason)) => {
            log::info!(
                "[qemu-exit] [kind end] [detail {}]",
                shutdown_cause_detail(&reason)
            );
            ExitKind::Ok
        }
        Ok(QemuExitReason::Breakpoint(reason)) => {
            log::info!("[qemu-exit] [kind breakpoint] [detail trigger address {reason:#x}]");
            ExitKind::Ok
        }
        Err(err) => {
            log::info!("[qemu-exit] [kind error] [detail {:?}]", err);
            ExitKind::Crash
        }
    };
    let mut observers = ();
    emulator.post_exec(&input, &mut observers, &mut state, &mut exit_kind);

    let resolver = AddressResolver::new(&qemu);

    match exit_kind {
        ExitKind::Crash => log::info!("[exit] [result crash]"),
        ExitKind::Ok => log::info!("[exit] [result ok]"),
        ExitKind::Timeout => log::info!("[exit] [result timeout]"),
        other => log::info!("[exit] [result {other:?}]"),
    }

    if matches!(exit_kind, ExitKind::Crash) {
        log::info!("stacktrace:");
        if let Some(frames) = FullBacktraceCollector::backtrace() {
            for (idx, addr) in frames.iter().rev().enumerate() {
                log::info!(
                    "[stacktrace] [idx {idx}] [addr {addr:#x}] [symbol {}]",
                    resolver.resolve(*addr)
                );
            }
            if let Some((idx, addr)) = find_last_guest_frame(&frames) {
                log::info!(
                    "[fault-addr] [idx {idx}] [addr {addr:#x}] [symbol {}]",
                    resolver.resolve(addr)
                );
            }
        } else {
            log::info!("[error] no stack collected");
        }
    }

    if let Some(addr) = patch_loc_runtime {
        let summary = patch_summary();
        log::info!(
            "[patch-cov] [location {addr:#x}] [covered {}] [hits {}]",
            PATCH_LOC_COVERED.load(Ordering::Relaxed),
            summary.hits
        );
        if summary.hits > 0 {
            if summary.function_call_entries.is_empty() {
                log::info!(
                    "[patch-func] [location {addr:#x}] [entry 0] [hits {}]",
                    summary.unknown_hits
                );
            } else {
                for (entry, calls) in &summary.function_call_entries {
                    log::info!(
                        "[patch-func] [location {addr:#x}] [entry {entry:#x}] [hits {calls}]"
                    );
                }
            }
        }
    }

    if opts.trace_basic_blocks {
        let basic_blocks = basic_block_summary();
        log::info!("[bb] [count {}]", basic_blocks.len());
        for (idx, (addr, hits)) in basic_blocks.iter().enumerate() {
            log::info!("[bb] [idx {idx}] [addr {addr:#x}] [hits {hits}]");
        }
    }

    Ok(())
}
