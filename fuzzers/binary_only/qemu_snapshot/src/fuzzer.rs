//! Simple single-input QEMU harness:
//!
//! Usage:
//!   qemu_snapshot <program> <input_path>
//!
//! This runs the given `program` under QEMU (usermode) with the provided
//! `input_path` as argv[1], and logs executed translation blocks (guest PCs).
#![cfg(target_os = "linux")]

use std::{env, process};

use libafl::Error;
use libafl_bolts::tuples::tuple_list;

use libafl_qemu::{
    elf::EasyElf,
    Emulator, Qemu, QemuHooks, GuestAddr, QemuExitReason, Regs, NopEmulatorDriver, NopSnapshotManager,
};
use libafl_qemu::command::NopCommandManager;

/// Called when a translation block (TB) is generated.
/// We just log the guest PC for the generated TB and return an id (here we
/// choose to return the PC itself).
unsafe extern "C" fn log_block_gen(_data: u64, pc: GuestAddr) -> u64 {
    eprintln!("[QEMU][TB_GEN] guest_pc = 0x{pc:x}");
    pc as u64
}

/// Called when a translation block is executed.
/// The `id` is whatever `log_block_gen` returned (here the guest PC).
unsafe extern "C" fn log_block_exec(_data: u64, id: u64) {
    // Try to read the current PC register to show the runtime PC as well.
    if let Some(q) = Qemu::get() {
        let current_pc = match q.read_reg(Regs::Pc) {
            Ok(v) => v,
            Err(_) => 0u64,
        };
        eprintln!(
            "[QEMU][TB_EXEC] guest_pc = 0x{id:x} (current_pc = 0x{current_pc:x})"
        );
    } else {
        eprintln!("[QEMU][TB_EXEC] guest_pc = 0x{id:x}");
    }
}

fn usage_and_exit() -> ! {
    eprintln!("Usage: qemu_snapshot <program> <input_path>");
    process::exit(1)
}

pub fn run() -> Result<(), Error> {
    // Expect exactly two args: program and input file path. We will pass the input path
    // as the first argument to the target program (so it can open/read it itself).
    let mut args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        usage_and_exit();
    }

    // The QEMU CLI expects the first element to be the running program path
    // (the wrapper). Keep `self_bin` and build argv as [self_bin, target, input].
    let self_bin = args.remove(0);
    let program = args.remove(0);
    let input_path = args.remove(0);

    eprintln!("self: {self_bin}, program: {program}, input: {input_path}");

    let qemu_argv = vec![self_bin.clone(), program.clone(), input_path.clone()];

    // Empty modules tuple to allow generic inference
    let modules = tuple_list!();

    // Build the emulator configured to run the target program with provided argv.
    // Provide an explicit type annotation so the compiler can infer all type params.
    // Pass a slice to `qemu_parameters` so `Into<QemuParams>` uses the `From<&[T]>` impl
    // and avoids ambiguous TryInto/Into type inference for `QP`.
    let emulator: Emulator<
        (),
        NopCommandManager,
        NopEmulatorDriver,
        (),
        (),
        (),
        NopSnapshotManager,
    > = Emulator::empty()
        .qemu_parameters(qemu_argv.as_slice())
        .modules(modules)
        .build()
        .expect("QEMU initialization failed");

    let qemu = emulator.qemu();
    
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;
    let model_malloc_max_addr = elf  
        .resolve_symbol("model_malloc_max", qemu.load_addr())  
        .expect("Symbol model_malloc_max not found");  
    eprintln!("model_malloc_max @ 0x{model_malloc_max_addr:x}");
    let load = qemu.load_addr();
    eprintln!("[QEMU] load_addr = 0x{load:x}");

    // Install a basic-block (translation block) logging hook if hooks are available.
    if let Some(hooks) = QemuHooks::get() {
        // data = 0, generator = Some(log_block_gen), post_gen = None, exec = Some(log_block_exec)
        hooks.add_block_hooks(0u64, Some(log_block_gen), None, Some(log_block_exec));
        eprintln!("Installed TB generation/execution hooks.");
    } else {
        eprintln!("QemuHooks not initialized; block logging disabled");
    }

    // Run the target under QEMU once and log TBs.
    unsafe {
        match qemu.run() {
            Ok(QemuExitReason::End(_)) => {
                eprintln!("QEMU: target terminated normally");
            }
            Ok(QemuExitReason::Breakpoint(addr)) => {
                eprintln!("QEMU: hit breakpoint at 0x{addr:x}");
            }
            Ok(other) => {
                eprintln!("QEMU exited with: {other:?}");
            }
            Err(e) => {
                eprintln!("QEMU run error: {e:?}");
                process::exit(3);
            }
        }
    }
    Ok(())
}
