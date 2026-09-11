# Testing

usbtrace CI today covers **build + `usbtrace list`** (see `.github/workflows/ci.yml`).
Runtime BPF load/attach is left to local smoke scripts — they need root, BTF, and
(optionally) an ARM32 QEMU guest. Nothing here is required to merge a PR unless
you touch the load path; then please run the host smoke at least.

## Host smoke (recommended)

Loads every module briefly and sends `SIGTERM`. No USB device required. Hooks
missing on the running kernel are **SKIP**, not FAIL.

```bash
make                          # native binary → build/usbtrace
sudo ./scripts/smoke-load.sh
sudo ./scripts/smoke-load.sh --quick   # urb lifecycle enum power only
```

`make smoke` is a thin wrapper around the same script (still needs a root-capable
sudo from your shell).

Environment:

| Variable | Default | Meaning |
|----------|---------|---------|
| `USBTRACE_BIN` | `build/usbtrace` | Binary under test |
| `SMOKE_TIMEOUT` | `3` | Seconds per module before TERM |
| `SMOKE_DIAG_TIMEOUT` | `6` | Timeout for `diag` |

## ARM32 QEMU smoke (optional)

Exercises the **perf + ARM32** path (32-bit `pt_regs`, `USBTRACE_EVENTS=perf`).
Guest initramfs runs the same core-module load smoke.

Host packages: `qemu-system-arm`, `git`, `curl`, `gzip`, `cpio`, `dwarves`
(pahole), and an armhf cross GCC on `PATH` (`arm-linux-gnueabihf-` or similar).

**Use mainline stable `linux-5.4.y` for the guest kernel**, not a board BSP tree.
Vendor trees (STM32/i.MX/…) turn on SoC drivers that break a `virt` link
(e.g. `stm32-dma` → undefined `__aeabi_uldivmod`).

```bash
# 1) Cross-build a static ARM perf binary (see docs/build.md)
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- \
     VMLINUX_BTF=/path/to/target/vmlinux \
     USBTRACE_EVENTS=perf USBTRACE_LINK=static
cp -f build/usbtrace dist/usbtrace-armv7-linux-perf   # or set USBTRACE_BIN=

# 2) Fetch mainline 5.4.y (once) and run QEMU smoke
./scripts/qemu-arm32/fetch-kernel.sh
export KERNEL_SRC=$PWD/testdata/qemu-arm32/linux-5.4
export CROSS_COMPILE=arm-linux-gnueabihf-
export USBTRACE_BIN=./dist/usbtrace-armv7-linux-perf
./scripts/smoke-qemu-arm32.sh
```

If `KERNEL_SRC` is unset and there is no cached `zImage`, `smoke-qemu-arm32.sh`
calls `fetch-kernel.sh` itself. Or pass a prebuilt virt `zImage`:

```bash
QEMU_ARM32_KERNEL=/path/to/zImage USBTRACE_BIN=./dist/usbtrace-armv7-linux-perf \
  ./scripts/smoke-qemu-arm32.sh
```

Details: [`scripts/qemu-arm32/README.md`](../scripts/qemu-arm32/README.md).

Pass criterion: serial log contains `=== usbtrace-qemu-arm32 PASS ===`
(`testdata/qemu-arm32/last-serial.log`). The harness uses `-serial file:…`
rather than `-nographic`, so `timeout` does not leave QEMU stuck with an empty log.

## What these smokes do *not* cover

- Real USB traffic / gadget enumeration (needs hardware or `dummy_hcd` + ConfigFS)
- Verifier edge cases on every LTS kernel
- Full `diag` rule corpus

Those remain manual or future CI (see `docs/roadmap.md`).
