# qemu_patch_executor
A simple executor that runs a patched binary in qemu and collects data required for binradar.

## Patch Format
Patches should be applied to the guest binary before running the executor using `e9tool`. The patch format is defined as follows:
```shell
bin/e9compile CWE-369.c # produces CWE-369
e9tool -100 -M addr=0x456845 -P 'if dest(op[0])@CWE-369 goto' ./nm.orig -o nm.patched
```
Example patch file content (`CWE-369.c`):
```c
#include "stdlib.c"

#define MAGIC_VALUE_PATCH 123456
#define DEST_ADDR 0x4567da
static const uint64_t *dest_shm = NULL;
static uint64_t env_patch_id = 0;
static int patch_fd = 2;

/*
 * Get an environment variable and parse as a number.
 * Return 0 on error.
 */
static uint64_t getenvull(const char *name)
{
	const char *const str = getenv(name);
	if (str == NULL)
		return 0ULL;
	errno = 0;
	const uint64_t ull = strtoull(str, NULL, 0);
	if (errno)
		return 0ULL;
	return ull;
}

/*
 * Attatch dest_shm to the shared memory specified
 * by the environment variable DEST_SHM_KEY,
 * if it is defined and exists.
 */
void init(int argc, const char *const *argv, char **envp)
{
	environ = envp;
	env_patch_id = getenvull("PATCH_ID");

	uint64_t s = getenvull("PATCH_FD");
	if (s != 0) {
		patch_fd = (int)s;
	}
	
	if (env_patch_id != MAGIC_VALUE_PATCH) {
		return;
	}

	const key_t dest_shm_key = getenvull("DEST_SHM_KEY");
	if (dest_shm_key) {
		const int dest_shm_id = shmget(dest_shm_key, 8, 0666);
		if (dest_shm_id >= 0)
			dest_shm = shmat(dest_shm_id, NULL, 0);
	}
}

/* Use with e9tool -P 'if dest(op[0])@CWE-369 goto' */
const void *dest(int64_t divisor)
{
	uint64_t patch_id = env_patch_id;
	if (patch_id == MAGIC_VALUE_PATCH) {
		patch_id = dest_shm ? *dest_shm : 0;
	}
	int branch_taken = 0;
	switch (patch_id) {
		case 1:
		    branch_taken = (divisor != 0);
			break;
		case 2:
		    branch_taken = (divisor > 67);
		    break;
		case 0:
		default:
			branch_taken = 0;
	}
	char buf[64];
	int n = snprintf(buf, sizeof(buf), "\n[patch] [id %lu] [br %d]\n", patch_id, branch_taken);
	write(2, buf, n);
	return branch_taken ? NULL : (const void *)DEST_ADDR;
}
```

## Usage
```bash
cargo build --release
./target/release/qemu_patch_executor --input /path/to/poc/input --patch-loc 0x456845 --patch-func-entry 0x456220 --trampoline-start 0x70001000 ./nm.patched -- -l @@
```
- `--input` specifies the path to the input file that will be used as an argument for the guest binary.
- `--patch-loc` specifies the address of the instruction to be patched in the guest binary.
- `--patch-func-entry` specifies the address of the patched function entry point.
- `--trampoline-start` specifies the address where the trampoline code will be placed.
- `./nm.patched` is the path to the patched guest binary that will be executed in qemu.
- `--options --for --guest-binary` are the options that will be passed to the guest binary. The `@@` will be replaced with the path to the input file specified by `--input`.

## Output
```python
import sbsv
parser = sbsv.parser()
parser.add_custom_type("hex", lambda x: int(x, 16))
```
