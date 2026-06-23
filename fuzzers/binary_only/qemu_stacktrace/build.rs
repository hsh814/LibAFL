use std::path::PathBuf;
use std::process::Command;

const PATCH_SYMS: &[&str] = &[
    "patch_aligned_alloc",
    "patch_atoi",
    "patch_atol",
    "patch_atoll",
    "patch_calloc",
    "patch_free",
    "patch_malloc",
    "patch_malloc_usable_size",
    "patch_memalign",
    "patch_memset",
    "patch_mmap",
    "patch_munmap",
    "patch_posix_memalign",
    "patch_pvalloc",
    "patch_read",
    "patch_realloc",
    "patch_reallocarray",
    "patch_valloc",
    "patch_write",
];

const FINAL_SYMS: &[&str] = &[
    "aligned_alloc",
    "atoi",
    "atol",
    "atoll",
    "calloc",
    "free",
    "malloc",
    "malloc_usable_size",
    "memalign",
    "memset",
    "mmap",
    "munmap",
    "posix_memalign",
    "pvalloc",
    "read",
    "realloc",
    "reallocarray",
    "valloc",
    "write",
];

fn run(cmd: &mut Command, desc: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to {desc}: {e}"));
    assert!(
        status.success(),
        "{desc} failed (exit code: {:?})",
        status.code()
    );
}

fn main() {
    let profile = std::env::var("PROFILE").unwrap();
    let profile_dir = if profile == "debug" {
        "debug"
    } else {
        "release"
    };
    let cargo_profile = if profile == "release" {
        "release"
    } else {
        "dev"
    };

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let libafl_dir = manifest_dir.join("../../..");
    let asan_dir = libafl_dir.join("crates/libafl_qemu/libafl_qemu_asan");
    let guest_source_dir = asan_dir.join("libafl_qemu_asan_guest");
    let asan_target_dir = asan_dir.join("target");
    let target_out = asan_target_dir
        .join("x86_64-unknown-linux-gnu")
        .join(profile_dir);

    let cross_cc = "x86_64-linux-gnu-gcc";
    let cross_objcopy = "objcopy -F elf64-x86-64";
    let cross_strip = "strip -F elf64-x86-64";
    let asan_cflags = "-m64 -no-pie -Wl,--no-relax -mcmodel=large -fno-stack-protector";

    std::fs::create_dir_all(&target_out).unwrap();

    // Build libafl_qemu_asan_guest (staticlib) from the asan workspace.
    // libafl_asan_libc is a path dependency and gets built automatically with
    // the asan workspace's profile settings (which include panic="abort").
    run(
        Command::new("cargo")
            .args([
                "build",
                "--package",
                "libafl_qemu_asan_guest",
                "--target",
                "x86_64-unknown-linux-gnu",
            ])
            .arg("--profile")
            .arg(cargo_profile)
            .arg("--target-dir")
            .arg(&asan_target_dir)
            .arg("--manifest-path")
            .arg(asan_dir.join("Cargo.toml")),
        "build libafl_qemu_asan_guest (and deps: libafl_asan_libc, etc.)",
    );

    // rel_guest: libafl_qemu_asan_guest.a → .rel (relocatable)
    run(
        Command::new(cross_cc)
            .args(asan_cflags.split_whitespace())
            .args(["-r", "-nodefaultlibs", "-nostartfiles", "-nostdlib", "-g"])
            .args(PATCH_SYMS.iter().flat_map(|s| ["-u", s]))
            .arg("-o")
            .arg(target_out.join("libafl_qemu_asan_guest.rel"))
            .arg(target_out.join("libafl_qemu_asan_guest.a")),
        "rel_guest (link relocatable)",
    );

    // rename_guest: rename patch_* → base and base → real_*
    run(
        Command::new("sh").arg("-c").arg(format!(
            "{} --redefine-syms={} --redefine-syms={} {} {}",
            cross_objcopy,
            guest_source_dir.join("rename_real.syms").display(),
            guest_source_dir.join("rename_patch.syms").display(),
            target_out.join("libafl_qemu_asan_guest.rel").display(),
            target_out.join("libafl_qemu_asan_guest.renamed").display(),
        )),
        "rename_guest (objcopy rename symbols)",
    );

    // link_guest: final link into _libafl_qemu_asan_guest.so
    run(
        Command::new(cross_cc)
            .args([
                "-shared",
                "-nodefaultlibs",
                "-nostartfiles",
                "-nostdlib",
                "-g",
            ])
            .args(FINAL_SYMS.iter().flat_map(|s| ["-u", s]))
            .arg(format!(
                "-Wl,--version-script={}",
                guest_source_dir.join("guest.map").display()
            ))
            .args(["-Wl,--gc-sections", "-Wl,--no-undefined"])
            .arg("-o")
            .arg(target_out.join("_libafl_qemu_asan_guest.so"))
            .arg(target_out.join("libafl_qemu_asan_guest.renamed"))
            .arg("-L")
            .arg(&target_out)
            .arg("-lafl_asan_libc"),
        "link_guest (final link .so)",
    );

    // strip_guest: produce final libafl_qemu_asan_guest.so
    run(
        Command::new("sh").arg("-c").arg(format!(
            "{} --strip-unneeded -o {} {}",
            cross_strip,
            target_out.join("libafl_qemu_asan_guest.so").display(),
            target_out.join("_libafl_qemu_asan_guest.so").display(),
        )),
        "strip_guest (strip .so)",
    );

    // Copy to fuzzer's target output directory (next to the binary)
    let fuzzer_target_dir = manifest_dir.join("target").join(profile_dir);
    std::fs::create_dir_all(&fuzzer_target_dir).unwrap();
    std::fs::copy(
        target_out.join("libafl_qemu_asan_guest.so"),
        fuzzer_target_dir.join("libafl_qemu_asan_guest.so"),
    )
    .unwrap();
}
