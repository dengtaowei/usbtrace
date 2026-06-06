# usbtrace architecture

`usbtrace` is an eBPF-based USB subsystem tracer & diagnostic tool for Linux
BSP work, inspired by [nettrace](https://github.com/OpenCloudOS/nettrace). Where
nettrace tracks an `skb` through the network stack, usbtrace tracks USB device
lifecycle, URBs, power events, and class-level traffic (UVC/UAC/HID/storage),
and correlates them into diagnoses via the `diag` rule engine.

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
│   ├── run.h                #   generic load/attach/poll harness (usbtrace_run)
│   ├── cli.h                #   shared --vid/--pid/--json + formatters
│   ├── probe.h              #   hook feature-probe + per-program degradation
│   ├── filter.bpf.h         #   BPF-side device filter helper
│   ├── class.h / class_*.h  #   class-traffic foundation (uvc/uac/hid/storage)
│   └── log.h                #   logging helpers
├── src/
│   ├── main.c               # CLI: global opts, subcommand dispatch
│   ├── module.c             # module registry implementation
│   ├── run.c                # usbtrace_run() harness (shared by all modules)
│   ├── usbtrace_cli.c       # shared CLI helpers
│   ├── probe.c              # hook feature-probe / graceful degradation
│   ├── class_stream.c       # shared class-traffic event consumer
│   └── modules/             # one subdir per module
│       └── urb/             #   reference module (URB submit/complete)
│           ├── urb.h        #     shared kernel<->user types
│           ├── urb.bpf.c    #     BPF program (kprobes on USB core)
│           └── urb.c        #     user space: open + usbtrace_run + register
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
  ├─ libbpf_set_print()         route libbpf logs once for every module
  ├─ parse global opts (-v/-j/-V/-h)
  ├─ resolve subcommand -> usbtrace_find_module(name)
  ├─ module->parse_args(argc, argv)
  └─ module->run(&running)
        ├─ <mod>_bpf__open()        open skeleton
        ├─ set ->rodata config      (filters etc.)
        ├─ usbtrace_run(&(struct usbtrace_run){ ... }, running)   (src/run.c)
        │     ├─ usbtrace_autoload_filter()       disable hooks absent on this kernel
        │     ├─ bpf_object__load_skeleton()     load + CO-RE relocate
        │     ├─ bpf_object__attach_skeleton()   attach the surviving probes
        │     ├─ ring_buffer__new(events, on_event, ctx)
        │     ├─ on_start()        (optional: "tracing..." + header)
        │     ├─ poll loop until Ctrl-C / error
        │     └─ on_stop()         (optional: summary)
        └─ <mod>_bpf__destroy()     module owns open/destroy
```

The poll loop, attach, ring-buffer setup, error handling and teardown live once
in `usbtrace_run()` (`include/usbtrace/run.h`). A module's `run()` only opens its
skeleton, sets its `.rodata` config, and calls the harness — so every module
behaves identically and a new one is a few lines.

## Graceful degradation (per-program feature probing)

"One CO-RE binary across kernels" means a hook a module wants may not exist on
the running kernel — a function renamed/removed between versions, or a driver
whose completion symbol is absent (e.g. `usb_stor_blocking_completion` when the
device uses the `uas` driver instead of `usb-storage`). Failing the whole module
for one missing hook would be wrong, especially for multi-hook modules (`hid`
has `hid_irq_in` + `hid_irq_out`; `urb` has submit + giveback).

So before loading, `usbtrace_autoload_filter()` (`src/probe.c`) walks every
program in the opened `bpf_object`, reads each program's `SEC()` name, and checks
whether its attach target is present:

- **functions** (`kprobe`/`kretprobe`/`fentry`/`fexit`) — looked up in
  `/proc/kallsyms` ∪ `…/available_filter_functions` (union; a module function
  shows up only while its module is loaded, which is exactly the attach-time
  truth we want);
- **tracepoints** (`tracepoint/<subsys>/<event>`) — checked via tracefs
  `events/<subsys>/<event>/`.

A program whose target is provably absent has `bpf_program__set_autoload(false)`
set, so libbpf skips it at both load and attach; the rest of the module loads
normally. The check is **tri-state and fails open**: if availability can't be
determined (lists unreadable, or an unrecognized `SEC()` form) the program stays
enabled, so we never wrongly disable a hook that would have worked. `usbtrace_run`
treats "zero programs survived" as a clean error; `diag` skips just that source
and keeps the others running. This same pass also feeds the future module-BTF
tier (e.g. vb2/v4l2) so optional layers light up only where supported — see
[uvc.md](uvc.md).

## Module interface

A module is a `struct usbtrace_module` (see `include/usbtrace/module.h`) with
`name`, `summary`, optional `parse_args`/`usage`, and a required `run`. It
self-registers via `USBTRACE_MODULE_REGISTER(var)` (a `__attribute__((constructor))`
that appends to a global linked list before `main`). The core never references a
concrete module directly, so new modules are purely additive.

## Shared user-space infrastructure

To keep modules consistent and small, common behavior is factored out:

| Piece | File | Provides |
|-------|------|----------|
| Run harness | `run.h` / `run.c` | `usbtrace_run()`: feature-probe → load → attach → poll loop → teardown |
| Hook probing | `probe.h` / `probe.c` | `usbtrace_autoload_filter()`: per-program graceful degradation (see below) |
| CLI helpers | `cli.h` / `usbtrace_cli.c` | `--vid/--pid` parsing (`usbtrace_filter_parse`), `--json`, speed/JSON formatters, libbpf log routing |
| Class consumer | `class_*.h` / `class_stream.c` | normalized class-traffic record + shared event printer/summary for uvc/uac/hid/storage (see [class.md](class.md)) |

`diag` is the one module with a different loop (it merges several skeletons and
runs a periodic deadline tick), so it drives the skeleton ABI directly instead
of `usbtrace_run()`; it still reuses the CLI and class types. See
[diag.md](diag.md).

## Event transport

All modules push records to a `BPF_MAP_TYPE_RINGBUF`. Every record begins with a
`struct usbtrace_event_hdr { kind; size; ts_ns; }` (see `common.h`) so a single
ring buffer can carry heterogeneous records and the user side can route by
`kind`. The demo `urb` module embeds this header in `struct urb_event`.

See `docs/modules.md` for how to add a module, and the planned module roadmap.
