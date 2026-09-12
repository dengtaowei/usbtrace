# Building usbtrace

## Dependencies

Vendored as git submodules (pinned):

| Component | Version | Why |
|-----------|---------|-----|
| libbpf    | v1.5.0  | CO-RE, ring/perf buffer, skeleton runtime. Stable, works on kernels ≥ 5.4. |
| bpftool   | libbpf/bpftool (tracks libbpf) | `gen skeleton`, `btf dump` (vmlinux.h). |

Host toolchain (install via `make deps` or `scripts/setup-deps.sh`):

- `clang` + `llvm` — **clang ≥ 12 required, ≥ 14 recommended** (BPF target
  compilation). clang 12 is the floor because earlier releases mis-emit BTF for
  CO-RE; clang 10/11 only work if every `const volatile ... cfg` global is
  zero-initialized (`= {}`). On Ubuntu 20.04: `apt install clang-12` then build
  with `make CLANG=clang-12`.
- `libelf-dev`, `zlib1g-dev`, `libssl-dev` (libbpf/bpftool link deps)
- `libyaml-dev` (the `diag` module's YAML knowledge base parser; `-lyaml`)
- `libzstd-dev` (static link: elfutils' `libelf.a` typically needs `-lzstd`)
- `gcc`, `make`, `pkg-config`
- kernel with **BTF** (`/sys/kernel/btf/vmlinux`); check `CONFIG_DEBUG_INFO_BTF=y`
- For kernels **< 5.8** (no BPF ringbuf): build with `USBTRACE_EVENTS=perf`
  (see `config.mk`)

The default link is **static** (`USBTRACE_LINK=static`): one binary, no
`libelf.so` / `libyaml.so` on the target. The `-dev` packages above ship the
`.a` files. `make USBTRACE_LINK=dynamic` if you prefer shared libraries.

## Native build

```bash
make deps        # one-time: toolchain + submodules
make             # builds build/usbtrace and a ./usbtrace symlink (ringbuf, static)
make USBTRACE_EVENTS=perf          # Linux 5.4 / no ringbuf
make USBTRACE_LINK=dynamic         # shared libelf / libyaml
sudo ./usbtrace list
sudo ./usbtrace urb            # demo
```

## Multi-arch / cross build

`ARCH` is auto-detected from `uname -m` and normalized to one of:
`x86` (x86_64/i686), `arm` (armv7), `arm64` (aarch64).

Cross-compiling for a target needs three things: a cross `gcc`, the target's
`vmlinux` BTF (for `vmlinux.h`), and target `libelf`/`zlib` (and `libyaml`
for `diag`, or a static libyaml via `EXTRA_CFLAGS`/`LDFLAGS`).

```bash
# arm64
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     VMLINUX_BTF=/path/to/target/vmlinux

# arm (32-bit), Linux 5.4 BSP example
make ARCH=arm CROSS_COMPILE=arm-buildroot-linux-gnueabihf- \
     VMLINUX_BTF=/path/to/target/vmlinux \
     USBTRACE_EVENTS=perf \
     EXTRA_CFLAGS='-I/path/to/staging/include' \
     LDFLAGS='-L/path/to/staging/lib'
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
- Do **not** override `CFLAGS` on the make command line (drops
  `USBTRACE_USE_PERF` / version). Use `EXTRA_CFLAGS` and `LDFLAGS` for
  sysroot include/lib paths.
- `USBTRACE_PERF_PAGES` (default 64) sizes each CPU's perf buffer when using
  the perf backend.
- `USBTRACE_LINK=static` (default) produces a self-contained binary; use
  `dynamic` to link against the target's shared libraries.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `clang: command not found` | `make deps` (or install clang) |
| `yaml.h: No such file` / `-lyaml` link error | install `libyaml-dev` (or `make deps`); for static also need `libyaml.a` |
| `cannot find -lzstd` / undefined `ZSTD_*` when static | install `libzstd-dev`; or `make USBTRACE_LINK=dynamic` |
| `file` still says `dynamically linked` | rebuild (`make` default is static); check `DONE ... link=static` |
| clang older than 12 | install `clang-12`+ and build with `make CLANG=clang-12` |
| `no BTF source` during VMLINUX | enable `CONFIG_DEBUG_INFO_BTF`, or pass `VMLINUX_BTF=` |
| `failed to create map ... RINGBUF` / load fail on 5.4 | build with `USBTRACE_EVENTS=perf` |
| `perf buffer lost N event(s) on cpu X` | raise `USBTRACE_PERF_PAGES` (e.g. 128) and rebuild |
| `failed to find BTF info for global/extern symbol 'cfg'` | upgrade to clang ≥ 12 (preferred); or zero-init the global as `const volatile struct ... cfg = {};` |
| `failed to load BPF skeleton` | run as root; verify BTF; check `dmesg` for verifier logs (`-v`) |
| permission denied loading BPF | run with `sudo`; on locked-down systems `kernel.unprivileged_bpf_disabled=2` requires root |
| `urb` silent on ARM32 under real USB traffic | fixed in `pt_regs.bpf.h`: multi-arg kprobes must not use `BPF_KPROBE(fn, a, b, …)` on 32-bit |
| `lifecycle` CONNECT `0000:0000` / no DISCONNECT on x86_64 | do not `__u32`-truncate kernel pointers; kretprobe return is `USBTRACE_PT_RET` (not PARM1) |
