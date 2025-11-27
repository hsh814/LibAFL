#![cfg(target_os = "linux")]

mod fuzzer;

fn main() {
    if let Err(err) = fuzzer::run() {
        eprintln!("Error: {err}");
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    panic!("qemu_snapshot is only supported on linux (qemu-user + libafl_qemu)");
}
