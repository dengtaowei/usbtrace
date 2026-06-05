# usbtrace modules

## Existing

| Module | Status | Hooks | Purpose |
|--------|--------|-------|---------|
| `urb`  | demo / working | kprobe `usb_submit_urb`, `__usb_hcd_giveback_urb` | URB submit/complete, submit→complete latency, per-device filter. Foundation for transfer-health diagnosis. |

## Roadmap (planned modules)

Ordered by value for BSP / bring-up work (see project notes):

| Module | Hooks (indicative) | Purpose |
|--------|--------------------|---------|
| `enum`    | `usb_alloc_dev`, `usb_set_device_state`, `hub_port_*`, `usb_probe_*` | Enumeration timeline: connect → GET_DESCRIPTOR → SET_ADDRESS → SET_CONFIG; where/why it fails. |
| `lifecycle` | `usb_disconnect`, driver `probe`/`disconnect`, devnode add/remove | Connect/disconnect/reset root-cause, re-enumeration tracking. |
| `power`   | `usb_autopm_*`, runtime suspend/resume vs URB activity | Autosuspend / resume-fail / remote-wakeup issues. |
| `hcd`     | xhci/dwc3 ring + port state | Controller-level expert view (advanced). |
| `gadget`  | `usb_ep_queue`, `usb_gadget_giveback_request`, `usb_gadget_set_state` | Device-side (UDC) request lifecycle. |
| `uac`     | snd-usb-audio paths + isoc URBs | USB Audio Class: underrun/overrun, isoc scheduling. |
| `uvc`     | uvcvideo paths + isoc URBs | USB Video Class: frame drops, bandwidth. |
| `hid`     | `hid_input_report`, int URBs | HID report flow / latency. |

`diag` mode (nettrace-style rule engine, e.g. "disconnect preceded by N bulk
errors → suspect link/power") is a cross-cutting layer to add once 2–3 trace
modules exist.

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
   - `<name>.c` — user space. Include `"<name>.skel.h"` (auto-generated),
     implement `parse_args`/`usage`/`run`, then:
     ```c
     static struct usbtrace_module <name>_module = {
         .name = "<name>", .summary = "...",
         .parse_args = ..., .usage = ..., .run = ...,
     };
     USBTRACE_MODULE_REGISTER(<name>_module);
     ```
3. Run `make`. The build auto-discovers `src/modules/*/*.bpf.c` and `*.c`,
   generates the skeleton, compiles and links it in. No Makefile edits needed.
4. `./build/usbtrace list` should now show your module.

### Skeleton naming

For `foo.bpf.c`, the build emits `foo.skel.h` whose generated type is
`struct foo_bpf` with `foo_bpf__open/load/attach/destroy`. Include it as
`#include "foo.skel.h"`.
