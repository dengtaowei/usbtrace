# usbtrace architecture

`usbtrace` is an eBPF-based USB subsystem tracer & diagnostic tool for Linux
BSP work, inspired by [nettrace](https://github.com/OpenCloudOS/nettrace). Where
nettrace tracks an `skb` through the network stack, usbtrace tracks USB device
lifecycle, URBs, power events, and (later) class-level traffic (UAC/UVC/HID/...).

## Design goals

1. **Modular** — every capability is a self-contained *module* (own BPF object
   + skeleton + CLI). Adding support for a new area = adding one directory under
   `src/modules/`, no core changes.
2. **CO-RE / portable** — built on libbpf + BTF so one binary runs across kernel
   versions and across **x86 / x86_64 / arm / arm64** without recompiling per
   target.
3. **Self-contained toolchain** — libbpf and bpftool are vendored as pinned git
   submodules (see `docs/build.md`), avoiding fragile distro packages.

## Layout

```
usbtrace/
├── Makefile                 # multi-arch build, auto-discovers modules
├── include/usbtrace/        # public headers shared across the codebase
│   ├── common.h             #   kernel<->user shared types (BPF-safe)
│   ├── module.h             #   module interface + registry
│   └── log.h                #   logging helpers
├── src/
│   ├── main.c               # CLI: global opts, subcommand dispatch
│   ├── module.c             # module registry implementation
│   └── modules/             # one subdir per module
│       └── urb/             #   demo module (URB submit/complete)
│           ├── urb.h        #     shared kernel<->user types
│           ├── urb.bpf.c    #     BPF program (kprobes on USB core)
│           └── urb.c        #     user space: load/attach/print + register
├── third_party/             # git submodules
│   ├── libbpf/  (v1.5.0)
│   └── bpftool/
├── bpf/vmlinux/<arch>/      # optional committed vmlinux.h for cross builds
├── scripts/                 # setup-deps.sh, run-demo.sh
└── docs/
```

## Runtime flow

```
main()                         (src/main.c)
  ├─ parse global opts (-v/-V/-h)
  ├─ resolve subcommand -> usbtrace_find_module(name)
  ├─ module->parse_args(argc, argv)
  └─ module->run(&running)
        ├─ <mod>_bpf__open()        open skeleton
        ├─ set ->rodata config      (filters etc.)
        ├─ <mod>_bpf__load()        load + CO-RE relocate
        ├─ <mod>_bpf__attach()      attach probes
        ├─ ring_buffer__new()       consume events
        └─ poll loop until Ctrl-C
```

## Module interface

A module is a `struct usbtrace_module` (see `include/usbtrace/module.h`) with
`name`, `summary`, optional `parse_args`/`usage`, and a required `run`. It
self-registers via `USBTRACE_MODULE_REGISTER(var)` (a `__attribute__((constructor))`
that appends to a global linked list before `main`). The core never references a
concrete module directly, so new modules are purely additive.

## Event transport

All modules push records to a `BPF_MAP_TYPE_RINGBUF`. Every record begins with a
`struct usbtrace_event_hdr { kind; size; ts_ns; }` (see `common.h`) so a single
ring buffer can carry heterogeneous records and the user side can route by
`kind`. The demo `urb` module embeds this header in `struct urb_event`.

See `docs/modules.md` for how to add a module, and the planned module roadmap.
