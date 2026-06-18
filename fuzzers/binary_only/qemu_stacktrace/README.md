# qemu_stacktrace
A simple executor that runs a binary in qemu and collects data required for binradar.

## Dependencies

The ASAN guest DSO must be built before use:

```bash
cd ../../../crates/libafl_qemu/libafl_qemu_asan && \
ARCH=x86_64 PROFILE=release just build
```

Then set `CUSTOM_LIBAFL_QEMU_ASAN_PATH` to point to the built `libafl_qemu_asan_guest.so`:

```bash
export CUSTOM_LIBAFL_QEMU_ASAN_PATH=/path/to/libafl_qemu_asan_guest.so
```

## Usage
```bash
cargo build --release
./target/release/qemu_stacktrace --input /path/to/poc/input --patch-loc 0x456845 --asan-guest ./buggy.bin -- -l @@
```

### Options
- `--input <PATH>` — Path to the input file used as an argument for the guest binary.
- `--patch-loc <ADDR>` — Address of the instruction to be patched in the guest binary.
- `--asan-guest` — Enable QEMU ASAN guest mode for the target binary.
- `--asan-include <RANGE>` — Restrict ASAN instrumentation to the given address range(s). Repeatable. Format: `0x400000-0x500000`.
- `--asan-exclude <RANGE>` — Exclude address range(s) from ASAN instrumentation. Repeatable. Mutually exclusive with `--asan-include`.
- `--trace-basic-blocks` — Log every basic block executed.
- `./buggy.bin` — Path to the guest binary. `@@` in trailing args is replaced with the input path.

## Output
```python
import sbsv
parser = sbsv.parser()
parser.add_custom_type("hex", lambda x: int(x, 16))
parser.add_schema("[patch-info] [set: bool] [location: hex]")
parser.add_schema("[exit] [result: str]")
parser.add_schema("[qemu-exit] [kind: str] [detail: str]")
parser.add_schema("[stacktrace] [idx: int] [addr: hex] [symbol: str]")
parser.add_schema("[patch-cov] [location: hex] [covered: bool] [hits: int]")
parser.add_schema("[patch-func] [location: hex] [entry: hex] [hits: int]")
parser.add_schema("[fault-addr] [idx: int] [addr: hex] [symbol: str]")
with open("stderr.sbsv", "r") as f:
    results = parser.load(f)
    print(results)
```
