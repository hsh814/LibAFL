use capstone::{
    arch::x86::X86OperandType, arch::BuildsCapstone, arch::DetailsArchInsn, Capstone, RegId,
};
use clap::Parser;
use libafl::{
    corpus::InMemoryCorpus,
    events::SimpleEventManager,
    executors::{Executor, ExitKind},
    feedbacks::CrashFeedback,
    fuzzer::StdFuzzer,
    inputs::{Input, NopInput},
    monitors::SimpleMonitor,
    schedulers::QueueScheduler,
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
        EmulatorModule, SnapshotModule,
    },
    Emulator, GuestAddr, NopEmulatorDriver, NopSnapshotManager, Qemu, QemuExitReason, Regs,
    TargetSignalHandling,
};
use std::{
    cell::RefCell,
    collections::BTreeSet,
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
}

#[derive(Debug, Default)]
struct RuntimeTraceState {
    function_stack: Vec<FunctionFrame>,
    patch_hits: usize,
    patch_unknown_hits: usize,
    patch_function_entries: BTreeSet<GuestAddr>,
}

impl RuntimeTraceState {
    fn reset(&mut self, root_entry: GuestAddr) {
        self.function_stack.clear();
        self.function_stack.push(FunctionFrame {
            entry: Some(root_entry),
            return_addr: 0,
        });
        self.patch_hits = 0;
        self.patch_unknown_hits = 0;
        self.patch_function_entries.clear();
    }

    fn on_call(&mut self, entry: Option<GuestAddr>, return_addr: GuestAddr) {
        self.function_stack
            .push(FunctionFrame { entry, return_addr });
    }

    fn on_ret(&mut self, return_addr: GuestAddr) {
        while self.function_stack.len() > 1 {
            let frame = self.function_stack.pop().unwrap();
            if frame.return_addr == return_addr {
                break;
            }
        }
    }

    fn current_function_entry(&self) -> Option<GuestAddr> {
        self.function_stack.last().and_then(|frame| frame.entry)
    }

    fn on_patch_hit(&mut self) {
        self.patch_hits += 1;
        if let Some(entry) = self.current_function_entry() {
            self.patch_function_entries.insert(entry);
        } else {
            self.patch_unknown_hits += 1;
        }
    }

    fn patch_summary(&self) -> PatchSummary {
        PatchSummary {
            hits: self.patch_hits,
            unknown_hits: self.patch_unknown_hits,
            function_entries: self.patch_function_entries.iter().copied().collect(),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct PatchSummary {
    hits: usize,
    unknown_hits: usize,
    function_entries: Vec<GuestAddr>,
}

std::thread_local! {
    static RUNTIME_TRACE_STATE: RefCell<RuntimeTraceState> =
        RefCell::new(RuntimeTraceState::default());
}

fn record_patch_hit() {
    RUNTIME_TRACE_STATE.with(|state| {
        state.borrow_mut().on_patch_hit();
    });
}

fn patch_summary() -> PatchSummary {
    RUNTIME_TRACE_STATE.with(|state| state.borrow().patch_summary())
}

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
                state.patch_hits = 0;
                state.patch_unknown_hits = 0;
                state.patch_function_entries.clear();
            }
        });
    }
}

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
    record_patch_hit();
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
    let runtime_function_tracker = RuntimeFunctionTracker::new();
    let modules = tuple_list!(
        SnapshotModule::new(),
        CallTracerModule::new(
            StdAddressFilter::default(),
            tuple_list!(full_backtrace, runtime_function_tracker)
        ),
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
        let summary = patch_summary();
        log::info!(
            "[patch-cov] [location {addr:#x}] [covered {}] [hits {}]",
            PATCH_LOC_COVERED.load(Ordering::Relaxed),
            summary.hits
        );
        if summary.hits > 0 {
            if summary.function_entries.is_empty() {
                log::info!(
                    "[patch-func] [location {addr:#x}] [entry unknown] [hits {}]",
                    summary.unknown_hits
                );
            } else if summary.function_entries.len() == 1 && summary.unknown_hits == 0 {
                log::info!(
                    "[patch-func] [location {addr:#x}] [entry {:#x}] [hits {}]",
                    summary.function_entries[0],
                    summary.hits
                );
            } else {
                let entries = summary
                    .function_entries
                    .iter()
                    .map(|entry| format!("{entry:#x}"))
                    .collect::<Vec<_>>()
                    .join(",");
                log::info!(
                    "[patch-func] [location {addr:#x}] [entries {entries}] [entry-count {}] [hits {}]",
                    summary.function_entries.len(),
                    summary.unknown_hits
                );
            }
        }
    }

    Ok(())
}
