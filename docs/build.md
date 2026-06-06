# Building usbtrace

## Dependencies

Vendored as git submodules (pinned):

| Component | Version | Why |
|-----------|---------|-----|
| libbpf    | v1.5.0  | CO-RE, ring buffer, skeleton runtime. Stable, works on kernels ≥ 5.4. |
| bpftool   | libbpf/bpftool (tracks libbpf) | `gen skeleton`, `btf dump` (vmlinux.h). |

Host toolchain (install via `make deps` or `scripts/setup-deps.sh`):

- `clang` + `llvm` — **clang ≥ 12 required, ≥ 14 recommended** (BPF target
  compilation). clang 12 is the floor because earlier releases mis-emit BTF for
  CO-RE; clang 10/11 only work if every `const volatile ... cfg` global is
  zero-initialized (`= {}`). On Ubuntu 20.04: `apt install clang-12` then build
  with `make CLANG=clang-12`.
- `libelf-dev`, `zlib1g-dev`, `libssl-dev` (libbpf/bpftool link deps)
- `libyaml-dev` (the `diag` module's YAML knowledge base parser; `-lyaml`)
- `gcc`, `make`, `pkg-config`
- kernel with **BTF** (`/sys/kernel/btf/vmlinux`); check `CONFIG_DEBUG_INFO_BTF=y`

## Native build

```bash
make deps        # one-time: toolchain + submodules
make             # builds build/usbtrace and a ./usbtrace symlink
sudo ./usbtrace list
sudo ./usbtrace urb            # demo
```

## Multi-arch / cross build

`ARCH` is auto-detected from `uname -m` and normalized to one of:
`x86` (x86_64/i686), `arm` (armv7), `arm64` (aarch64).

Cross-compiling for a target needs three things: a cross `gcc`, the target's
`vmlinux` BTF (for `vmlinux.h`), and target `libelf`/`zlib`.

```bash
# arm64
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     VMLINUX_BTF=/path/to/target/vmlinux

# arm (32-bit)
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- \
     VMLINUX_BTF=/path/to/target/vmlinux
```

Notes:
- **bpftool** is built as a host tool (used only at build time), so it always
  compiles for the build machine — no cross issues.
- **vmlinux.h** resolution order: `VMLINUX_BTF` > committed
  `bpf/vmlinux/<arch>/vmlinux.h` > running kernel `/sys/kernel/btf/vmlinux`.
  For reproducible cross builds, commit a per-arch `vmlinux.h` under
  `bpf/vmlinux/<arch>/` or always pass `VMLINUX_BTF`.
- The BPF object itself is CO-RE and arch-portable; `-D__TARGET_ARCH_<arch>`
  only selects the correct `PT_REGS_*` macros for kprobe argument access.
- For the user-space binary you must provide target `libelf`/`zlib`
  (e.g. multiarch packages or a sysroot via `CFLAGS`/`LDFLAGS`).

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `clang: command not found` | `make deps` (or install clang) |
| `yaml.h: No such file` / `-lyaml` link error | install `libyaml-dev` (or `make deps`) |
| clang older than 12 | install `clang-12`+ and build with `make CLANG=clang-12` |
| `no BTF source` during VMLINUX | enable `CONFIG_DEBUG_INFO_BTF`, or pass `VMLINUX_BTF=` |
| `failed to find BTF info for global/extern symbol 'cfg'` | upgrade to clang ≥ 12 (preferred); or zero-init the global as `const volatile struct ... cfg = {};` |
| `failed to load BPF skeleton` | run as root; verify BTF; check `dmesg` for verifier logs (`-v`) |
| permission denied loading BPF | run with `sudo`; on locked-down systems `kernel.unprivileged_bpf_disabled=2` requires root |
