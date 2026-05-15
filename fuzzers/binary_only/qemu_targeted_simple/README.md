# qemu_targeted_simple
A simple coverage-guided QEMU fuzzer for file-based targets. Inputs that hit the target address are saved under `out/reached`.
    

## Usage
```bash
cargo build --release
./target/release/qemu_targeted_simple --input /path/to/poc/input --target-loc 0x456845 --output out ./nm.orig -- -l @@
```
- `--input` points to the runtime input file that the guest reads through `@@`.
- `--output` is the work directory for the fuzzer.
- `out/seeds` stores the imported seed corpus.
- `out/reached` stores inputs that reached the target address.
- `--target-loc` is the address of the instruction to be targeted in the guest binary.
- `./nm.orig` is the guest binary executed by QEMU.
- `-l @@` are the guest arguments. The `@@` placeholder is replaced with the runtime input file path.

The current setup uses a standard coverage-guided queue plus havoc-style mutation. AFL++-style power scheduling can also be wired in later through LibAFL's power scheduler and power mutational stage.
