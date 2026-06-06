# Class-traffic modules (uvc / uac / hid / storage)

The class modules observe a USB **class driver's URB completion** to report
per-transfer health: status, isoc `error_count` (frame/sample corruption),
packets and bytes. They are deliberately built on one shared foundation so they
stay tiny, consistent, and trivially extensible — and so they all cooperate with
`diag` for free.

| Module | Driver | Hook(s) | Signal |
|--------|--------|---------|--------|
| `uvc` | uvcvideo | `uvc_video_complete` | video isoc errors / frame drops |
| `uac` | snd-usb-audio | `snd_complete_urb` | audio isoc errors / xruns (IN=capture, OUT=playback) |
| `hid` | usbhid | `hid_irq_in`, `hid_irq_out` | report flow & errors (OUT = SET_REPORT) |
| `storage` | usb-storage | `usb_stor_blocking_completion` | BOT bulk stalls/timeouts before SCSI reset |

```bash
sudo usbtrace uvc --all --vid 0x046d   # every video URB for one camera
sudo usbtrace uac                       # audio: anomalies only (quiet when healthy)
sudo usbtrace hid --all                 # HID report flow
sudo usbtrace storage                   # mass-storage transport errors
sudo usbtrace --json uvc | jq           # machine-readable
```

By default only "interesting" URBs (`status != 0` or `error_count > 0`) print, so
a healthy stream is silent; `--all` prints every completion. Every run ends with
a health summary (URBs / isoc errors / status errors / bytes).

## Architecture

```
<driver>_<complete>(struct urb *urb)            ← kprobe (per module)
        │  usbtrace_class_urb_emit() reads CORE types only (urb, urb->dev)
        ▼
struct class_urb_event { klass; status; error_count; packets; bytes; ... }
        │  one ringbuf per module, hdr.kind = USBTRACE_EVT_CLASS
        ▼
shared user consumer (class_stream.*)  → text/JSON + exit summary   (standalone)
        └────────────────────────────→ diag normalizes + correlates (cooperation)
```

Shared pieces (write once, reused by every class module):

| File | Role |
|------|------|
| `include/usbtrace/class.h` | normalized `struct class_urb_event`, `enum usbtrace_class`, shared `usbtrace_class_config` |
| `include/usbtrace/class_urb.bpf.h` | `usbtrace_class_urb_emit()` — reserve/fill/submit from a `struct urb *` |
| `include/usbtrace/class_stream.h` + `src/class_stream.c` | arg parsing, event print (text/JSON), health tally, summary |
| `include/usbtrace/run.h` | `usbtrace_run()` — the load/attach/poll harness shared with the core modules |

A module's own code is just a `.bpf.c` (declare ringbuf + cfg, one kprobe per
hook calling the helper) and a small `.c` (open skeleton, set filter, call
`usbtrace_run()` with `class_stream_on_event` + a summary callback).

## The module-BTF rule (the key constraint)

CO-RE relocations resolve against `/sys/kernel/btf/vmlinux`, which holds only
**built-in** types. Class drivers (uvcvideo, snd-usb-audio, usbhid, usb-storage)
are loadable modules; their private structs live in module BTF
(`/sys/kernel/btf/<module>`), **not** vmlinux BTF.

So every class hook here is a function whose argument is a **core** type
(`struct urb *`), and the shared helper reads only `urb` and `urb->dev`
(`struct usb_device`). This is why one helper works for all four drivers and
stays portable across kernels/arches.

**Rule of thumb when adding a hook:** pick a function that takes `struct urb *`
(or `struct usb_device *`). Driver-private structs need module BTF — avoid unless
necessary.

## Adding a new class module

Example: a hypothetical `printer` (usblp) module.

1. **`src/modules/printer/printer.bpf.c`** (~15 lines):
   ```c
   #include "vmlinux.h"
   #include <bpf/bpf_helpers.h>
   #include <bpf/bpf_tracing.h>
   #include "usbtrace/class_urb.bpf.h"
   char LICENSE[] SEC("license") = "GPL";
   const volatile struct usbtrace_class_config cfg = {};
   struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256*1024); } events SEC(".maps");
   SEC("kprobe/usblp_bulk_read")            // a urb-completion in usblp
   int BPF_KPROBE(on_complete, struct urb *urb)
   { return usbtrace_class_urb_emit(&events, urb, cfg.filter_vid, cfg.filter_pid, USBTRACE_CLASS_PRINTER); }
   ```
2. Add `USBTRACE_CLASS_PRINTER` to `enum usbtrace_class` (class.h) and a name in
   `usbtrace_class_str()` (class_stream.c).
3. **`src/modules/printer/printer.c`** — copy `uvc.c`, swap the skeleton type
   (`printer_bpf`) and the log strings. The body is just `printer_bpf__open()`,
   set the filter, `usbtrace_run()` with `class_stream_on_event` + a summary
   `on_stop`, then `printer_bpf__destroy()`.
4. `make`. The module is auto-discovered, registered, and shows in `usbtrace list`.

Multiple hooks (like `hid`'s in/out) are just multiple `SEC("kprobe/...")`
programs in the one `.bpf.c`; the harness attaches them all together.

### Wiring it into diag (cooperation)

Because all class modules share `class_urb_event`, diag needs **no new normalize
code**. Just register the source:

1. In `src/modules/diag/diag.c`: add `#include "printer.skel.h"`, one
   `DIAG_CLASS_SRC(printer_bpf)`, and one `DIAG_CLASS_ROW(printer_bpf, "printer")`
   in `diag_class_srcs[]`.
2. (Optional) add rules to `rules.yaml` using `kind: class, class: printer`.

That's it — the table-driven loader brings it up with graceful degradation, sets
the filter, and merges its ringbuf into the poll loop.

## diag cooperation & rules

diag loads every class source alongside urb/enum/lifecycle/power and normalizes
class events into the same per-device timeline. Rules address them with
`kind: class` and the `class:` field, e.g. the built-ins:

```yaml
- id: video-isoc-errors
  trigger: { kind: class, class: video }
  when:
    - kind: class
      match: { class: video, error_count: "!0" }   # count isoc-error URBs
      within_ms: 1000
      count_gte: 5
  conclusion: "Video device {vid}:{pid} saw {count} isoc-error URBs ..."
```

New rule fields available to class events: `class` (video/audio/hid/storage),
`error_count`, plus the existing `status`/`status_in`, `xfer_type`
(isoc/int/control/bulk), `ep`, `dir_in`, `actual`/`length`. See
[diag.md](diag.md) for the full schema.

## Event fields (`struct class_urb_event`)

| Field | Source | Meaning |
|-------|--------|---------|
| `klass` | module | `enum usbtrace_class` (video/audio/hid/storage) |
| `status` | `urb->status` | 0 = ok; negative = URB error |
| `error_count` | `urb->error_count` | isoc packets the HC flagged |
| `number_of_packets` | `urb->number_of_packets` | isoc packets (0 for INT/BULK) |
| `actual_length` | `urb->actual_length` | bytes transferred |
| `ep`/`dir_in`/`xfer_type` | `urb->pipe` | endpoint, direction, transfer type |
| `vid`/`pid`/`bus`/`dev` | `urb->dev` | device identity |

## Notes & limits

- `comm` reflects whatever ran when the completion IRQ fired (often
  `irq/..`/`swapper`/a kworker), **not** the owning app — completions run in
  interrupt context.
- UAS mass-storage devices use the `uas` driver, not `usb-storage`; the
  `storage` module covers BOT only (extend with a `uas` hook if needed).
- If a driver is not loaded its kprobe target is absent: a standalone module
  exits with an attach error, while `diag` warns and skips just that source
  (the other sources keep running).
