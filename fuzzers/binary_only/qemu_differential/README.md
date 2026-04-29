# QEMU differential tester

This tool compares an original and a patched binary under `libafl_qemu` user mode on Linux `x86_64`.

It is intended for cases where:
- only binaries are available,
- a patch site is known,
- the patch is a short conditional early-return or `exit(0)` sequence,
- the patched image may install trampoline code dynamically at runtime.

The tool does not rely on static disassembly of the trampoline. It places a runtime breakpoint at the supplied patch location and records whether the location is reached for each input.

## Usage

```sh
cargo run --release -- \
  --original /path/to/original \
  --patched /path/to/patched \
  --entry 0x401000 \
  --patch 0x401234 \
  --input ./testcases \
  -- @@ --more-option1 --more-option2 --output /tmp/out
```

Use the literal `@@` as the input placeholder. Omit it when the target reads input from stdin.

The `--input` argument can point to a single file or to a directory. Files are read as raw byte inputs.

The tool assumes the target function follows the standard `x86_64` System V calling convention and passes:
- argument 0: input pointer
- argument 1: input length
