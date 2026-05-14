# qemu_stacktrace
A simple executor that runs a binary in qemu and collects data required for binradar.

## Usage
```bash
cargo build --release
./target/release/qemu_stacktrace --input /path/to/poc/input --patch-loc 0x456845 ./buggy.bin -- --options --for --guest-binary @@
```
- `--input` specifies the path to the input file that will be used as an argument for the guest binary.
- `--patch-loc` specifies the address of the instruction to be patched in the guest binary.
- `./buggy.bin` is the path to the guest binary that will be executed in qemu.
- `--options --for --guest-binary` are the options that will be passed to the guest binary. The `@@` will be replaced with the path to the input file specified by `--input`.

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
