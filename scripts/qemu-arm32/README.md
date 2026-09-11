# QEMU ARM32 guest smoke

Optional maintainer tooling: boot `qemu-system-arm -M virt` with an initramfs
that contains a **static armhf `usbtrace` (perf backend)** and runs a short
load/attach smoke for `urb`, `lifecycle`, `enum`, and `power`.

This path exists because several production BSPs are **Linux 5.4 + ARMv7 +
perf events**; host x86_64/ringbuf smoke does not catch those bugs. It is
**not** wired into GitHub Actions.

Entry point: [`../smoke-qemu-arm32.sh`](../smoke-qemu-arm32.sh) or
`make smoke-qemu-arm32`.

## Kernel source: mainline 5.4.y only

```bash
./scripts/qemu-arm32/fetch-kernel.sh
# → testdata/qemu-arm32/linux-5.4  (stable linux-5.4.y, shallow clone)
# Default remote is https://github.com/gregkh/linux.git (faster than kernel.org).
# Override: LINUX_STABLE_URI=https://git.kernel.org/.../stable/linux.git
```

Do **not** point `KERNEL_SRC` at a vendor/BSP tree (STM32MP, i.MX, …). Those
defconfigs enable SoC drivers that do not belong in a QEMU `virt` guest and
often fail to link (missing libgcc helpers such as `__aeabi_uldivmod`).

If a previous attempt used a BSP worktree, wipe the cache and start over:

```bash
rm -rf testdata/qemu-arm32/{kbuild,linux-src,zImage,vmlinux}
```

## Inputs

| Variable | Required? | Meaning |
|----------|-----------|---------|
| `USBTRACE_BIN` | yes\* | Static ARM `usbtrace` built with `USBTRACE_EVENTS=perf` |
| `QEMU_ARM32_KERNEL` | no | Prebuilt `zImage` for `-M virt`; skips kernel compile |
| `KERNEL_SRC` | if building | Mainline/stable tree (from `fetch-kernel.sh`) |
| `CROSS_COMPILE` | if building | e.g. `arm-linux-gnueabihf-` (must be on `PATH`) |
| `QEMU_ARM32_CACHE` | no | Cache dir (default `testdata/qemu-arm32/`, gitignored) |
| `QEMU_TIMEOUT` | no | Host-side qemu kill timeout seconds (default `180`) |

Serial is written with `-display none -monitor none -serial file:…` (stdin
`</dev/null`). Avoid `-nographic` under `timeout`: the multiplexed console
can stop in job-control state `T` and leave `last-serial.log` empty.
| `FORCE_KERNEL_REBUILD` | no | `1` to ignore cached `zImage` |

\* If unset, the scripts look for `dist/usbtrace-armv7-linux-perf` then fail
with a build hint.

## Kernel options

[`kconfig.fragment`](kconfig.fragment) is merged onto `multi_v7_defconfig`. It
enables `ARCH_VIRT`, BTF, kprobes, USB core, PL011, and explicitly turns off
STM32 SoC options so a mistaken BSP tree fails fast at config check.

## BusyBox

`mkinitramfs.sh` downloads a pinned `busybox-armv7l` binary into the cache and
checks it against [`busybox.sha256`](busybox.sha256). Override with
`BUSYBOX_ARM=/path/to/busybox` to skip the download.

## Layout of the cache directory

```
testdata/qemu-arm32/          # gitignored
  linux-5.4/                  # from fetch-kernel.sh
  busybox
  initramfs.cpio.gz
  zImage
  vmlinux
  last-serial.log
  kbuild/
```
