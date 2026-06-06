# usbtrace

[![CI](https://github.com/dengtaowei/usbtrace/actions/workflows/ci.yml/badge.svg)](https://github.com/dengtaowei/usbtrace/actions/workflows/ci.yml)

eBPF-based USB subsystem tracer and diagnostic tool for Linux BSP.

Inspired by [nettrace](https://github.com/OpenCloudOS/nettrace): instead of
tracing an `skb` through the network stack, `usbtrace` traces USB device
lifecycle, URBs, power events, and (planned) class traffic (UAC/UVC/HID/...).
Built on **libbpf + CO-RE**, portable across kernels and across
**x86 / x86_64 / arm / arm64** from a single source.

## Status

Early scaffold. Working demo modules:

- **`urb`** — URB submit/complete + submit→complete latency
- **`enum`** — enumeration state timeline (connect → ... → configured)
- **`lifecycle`** — device connect / disconnect
- **`power`** — autosuspend / autoresume

All modules share `--vid/--pid` filtering and a global `--json` output mode.
See `docs/modules.md` for the roadmap.

## Quick start

```bash
make deps                 # one-time: toolchain + git submodules
make                      # build -> build/usbtrace (+ ./usbtrace symlink)

sudo ./usbtrace list      # show modules
sudo ./usbtrace urb       # trace all URBs (Ctrl-C to stop)
sudo ./usbtrace urb --vid 0x0403   # filter by vendor id (e.g. FTDI)
sudo ./usbtrace urb --submit       # also show submissions
sudo ./usbtrace power     # trace autosuspend/autoresume
sudo ./usbtrace --json power       # machine-readable JSON Lines (pipe to jq)
```

Requires **clang ≥ 12** (≥ 14 recommended), a kernel with BTF
(`CONFIG_DEBUG_INFO_BTF=y`), and root to load BPF. On older distros install a
newer clang and build with `make CLANG=clang-12`.

## Example output

```
EVENT  TYPE EP   D BYTES ...
CMPLT  BULK ep1  <    64/64    st=0     312.5us 0403:6001 1-3 python3
CMPLT  BULK ep2  >    32/32    st=0      88.0us 0403:6001 1-3 python3
```

## Documentation

- `docs/architecture.md` — design, layout, module interface
- `docs/modules.md` — module list + how to add one
- `docs/roadmap.md` — future modules & expansion requirements
- `docs/build.md` — dependencies, native & cross-arch builds
- `CONTRIBUTING.md` — build/test loop, commit convention, PR checks
- `.cursor/rules/*.mdc` — AI context (project conventions, travels with the repo)

## Layout

```
src/main.c            CLI dispatch        include/usbtrace/   shared headers
src/module.c          module registry     src/modules/<name>/ one dir per module
third_party/libbpf    submodule (v1.5.0)  third_party/bpftool submodule
```

## License

GPL-2.0 (BPF programs must be GPL-compatible to use kernel helpers).
