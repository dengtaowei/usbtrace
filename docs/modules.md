# usbtrace modules

## Existing

| Module | Status | Hooks | Purpose |
|--------|--------|-------|---------|
| `urb`  | working | kprobe `usb_submit_urb`, `usb_hcd_giveback_urb` | URB submit/complete, submit→complete latency, per-device filter. Foundation for transfer-health diagnosis. |
| `enum` | working | kprobe `usb_set_device_state` | Enumeration timeline: emits each `old → new` device-state transition so a stalled/failed bring-up is visible (e.g. stuck before `ADDRESS`/`CONFIGURED`). Per-device filter. |
| `lifecycle` | working | kprobe `usb_new_device`, `usb_disconnect` | Connect (enumeration done) / disconnect (teardown start) events with speed + topology path. Per-device filter. |
| `power` | working | kprobe `usb_autosuspend_device`, `usb_autoresume_device` | Runtime PM: autosuspend/autoresume events. Pair with `urb` to spot suspend-mid-transfer or resume storms. Per-device filter. |
| `diag`  | working | none (reuses urb/enum/lifecycle/power/class) | Cross-module rule engine: correlates events per device and emits conclusions + evidence chains from a YAML knowledge base. See [diag.md](diag.md). |
| `uvc`   | working | kprobe `uvc_video_complete` | USB Video Class: per-URB isoc health **plus frame-level diagnosis** (real FPS, frame drops/corruption, PTS/SCR jitter) by parsing UVC payload headers in BPF. Class-traffic module with added depth; see [class.md](class.md). |
| `uac`   | working | kprobe `snd_complete_urb` | USB Audio Class streaming health (isoc errors / xruns, capture+playback). See [class.md](class.md). |
| `hid`   | working | kprobe `hid_irq_in`, `hid_irq_out` | USB HID report flow (in/out, errors; OUT = SET_REPORT). See [class.md](class.md). |
| `storage` | working | kprobe `usb_stor_blocking_completion` | USB Mass Storage (BOT) transport health (stalls/timeouts before SCSI reset). See [class.md](class.md). |

All four class modules share one foundation (`include/usbtrace/class*.h`,
`src/class_stream.c`) and one normalized record (`struct class_urb_event`,
`hdr.kind = USBTRACE_EVT_CLASS`), which is what lets them all feed `diag` with no
per-module diag code. See [class.md](class.md) for the architecture and how to
add another class module.

## Roadmap (planned modules)

Ordered by value for BSP / bring-up work (see project notes):

| Module | Hooks (indicative) | Purpose |
|--------|--------------------|---------|
| `hcd`     | xhci/dwc3 ring + port state | Controller-level expert view (advanced). |
| `gadget`  | `usb_ep_queue`, `usb_gadget_giveback_request`, `usb_gadget_set_state` | Device-side (UDC) request lifecycle. |

`diag` mode (nettrace-style rule engine, e.g. "disconnect preceded by N bulk
errors → suspect link/power") is implemented as a cross-module consumer that
reuses the tracing modules' BPF programs. See [diag.md](diag.md) for the rule
schema and how to extend the knowledge base.

## Adding a module

1. Create `src/modules/<name>/`.
2. Add the three files:
   - `<name>.h` — types shared between BPF and user space. Include
     `"usbtrace/common.h"` and embed `struct usbtrace_event_hdr` as the first
     member of your event struct.
   - `<name>.bpf.c` — the BPF program. Start with:
     ```c
     #include "vmlinux.h"
     #include <bpf/bpf_helpers.h>
     #include <bpf/bpf_core_read.h>
     #include <bpf/bpf_tracing.h>
     #include "<name>.h"
     char LICENSE[] SEC("license") = "GPL";
     ```
     Use a `BPF_MAP_TYPE_RINGBUF` named `events`. Use `BPF_CORE_READ()` for all
     kernel struct field access (portability across arch/kernel).
   - `<name>.c` — user space. Include `"<name>.skel.h"` (auto-generated) and
     `"usbtrace/run.h"`. Do NOT hand-roll the load/attach/poll loop — open the
     skeleton, set `.rodata` config, and hand it to the shared `usbtrace_run()`
     harness so every module behaves identically:
     ```c
     static int <name>_run(volatile bool *running)
     {
         struct <name>_bpf *skel = <name>_bpf__open();
         int rc;

         if (!skel) { ut_err("failed to open BPF skeleton"); return 1; }
         skel->rodata->cfg.filter_vid = (unsigned short)opts.vid;
         skel->rodata->cfg.filter_pid = (unsigned short)opts.pid;

         rc = usbtrace_run(&(struct usbtrace_run){
             .skeleton = skel->skeleton,
             .events   = skel->maps.events,
             .on_event = handle_event,
             .on_start = <name>_on_start,  /* optional: "tracing..." + header */
         }, running);

         <name>_bpf__destroy(skel);
         return rc;
     }

     static struct usbtrace_module <name>_module = {
         .name = "<name>", .summary = "...",
         .parse_args = ..., .usage = ..., .run = <name>_run,
     };
     USBTRACE_MODULE_REGISTER(<name>_module);
     ```
3. Run `make`. The build auto-discovers `src/modules/*/*.bpf.c` and `*.c`,
   generates the skeleton, compiles and links it in. No Makefile edits needed.
4. `./build/usbtrace list` should now show your module.

> For a USB **class** driver (uvc/uac/hid/storage and friends), don't invent a
> new event — hook the driver's URB-completion callback and reuse the
> class-traffic foundation instead. It is far less code and gets `diag`
> cooperation for free. See [class.md](class.md).

> Cross-module consumers (like `diag`) may omit `.bpf.c` entirely and reuse other
> modules' skeletons. They can include another module's shared header as
> `"<name>/<name>.h"` (the build adds `-Isrc/modules`) and its generated skeleton
> as `"<name>.skel.h"`.

### Skeleton naming

For `foo.bpf.c`, the build emits `foo.skel.h` whose generated type is
`struct foo_bpf` with `foo_bpf__open/load/attach/destroy`. Include it as
`#include "foo.skel.h"`.

## Shared helpers (reuse these, don't re-implement)

Run harness — `#include "usbtrace/run.h"`:

- `usbtrace_run(&(struct usbtrace_run){...}, running)` — the one feature-probe →
  load → attach → ring buffer → poll loop → teardown for every single-skeleton
  module. Optional `on_start`/`on_stop` callbacks for a header line / exit
  summary. The module only opens and destroys its skeleton (see "Adding a module"
  above).
- **Graceful degradation is automatic.** The harness feature-probes every BPF
  program before load and disables any whose attach target is absent on this
  kernel, so a module with several hooks survives a single missing one (it only
  fails if *none* attach). You get this for free — just give each program a
  normal `SEC("kprobe/<func>")` / `SEC("tracepoint/<sub>/<evt>")`. Cross-module
  consumers that drive the skeleton ABI directly (like `diag`) call
  `usbtrace_autoload_filter(skel->obj)` themselves before `__load`; see
  `usbtrace/probe.h` and
  [architecture.md](architecture.md#graceful-degradation-per-program-feature-probing).

User space — `#include "usbtrace/cli.h"`:

- `usbtrace_filter_parse(argc, argv, &filt)` — full `--vid/--pid/--help` parser
  for the common case; `parse_args` becomes a one-liner. For extra options, fold
  `USBTRACE_FILTER_LONGOPTS` into your own `getopt_long` array and route each
  option through `usbtrace_filter_getopt()` (see `urb`'s `--submit`).
- `usbtrace_speed_str(speed)` — `enum usb_device_speed` → text.
- `usbtrace_json` (global, set by `--json`) + `usbtrace_json_escape()` — when
  `usbtrace_json` is set, emit one JSON object per line instead of text.
- `libbpf_set_print()` is already wired once in `main.c` (honors `-v`); modules
  do NOT call it.

BPF side — `#include "usbtrace/filter.bpf.h"` (after `vmlinux.h`):

- `usbtrace_dev_match(dev, fvid, fpid, &vid, &pid)` — single CO-RE read of
  `idVendor`/`idProduct` + the (vid,pid) match used by every module.
- Declare tunables as `const volatile struct <name>_config cfg = {};` — the
  `= {}` initializer is required for correct BTF emission on clang ≤ 10.

Class modules — `#include "usbtrace/class.h"` + `class_urb.bpf.h` (BPF) and
`class_stream.h` (user). One normalized record + emit helper + event consumer
shared by uvc/uac/hid/storage. See [class.md](class.md).

## Output format

Default is aligned human-readable text. The global `--json` flag (e.g.
`sudo usbtrace --json power`) switches every module to JSON Lines, suitable for
`jq`/scripts. Each line is a self-contained object keyed by `"event"`.
