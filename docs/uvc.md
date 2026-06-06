# uvc module blueprint (USB Video Class)

Living plan for `uvc`, written **value-first**: the goal is end-to-end video
pipeline diagnosis — from the wire to the application — so any "my camera is
laggy / dropping frames / stuttering" complaint can be localized to a specific
stage with evidence. Implementation constraints (BTF source, hook mechanism) are
notes, not scope limits; if a signal is worth having, it's in the plan.

> `uvc` started as a class-traffic module (see [class.md](class.md)) and remains
> compatible with it for the wire layer, but this blueprint treats `uvc` as the
> project's flagship **vertical**: the one subsystem we instrument top to bottom.

## The vision: full-pipeline observability

A UVC frame travels through four stages. Each can be the culprit, and today we
only see the first two:

```
 ┌─ stage 1 ─┐   ┌─ stage 2 ─┐   ┌─ stage 3 ─┐   ┌─ stage 4 ─┐
 USB wire    →   uvcvideo     →   videobuf2   →   application
 (isoc URBs)     (frame asm)      (vb2 queue)     (VIDIOC_DQBUF)
 ───covered───   ───covered───    ──── TO BUILD ─────────────
   bus/EMI/        driver           buffer            app too slow,
   bandwidth       organize         starvation        scheduling,
   device          /clock           host scheduling   userspace stall
```

The killer feature is the **gap analysis**: compare frame counts/timing at each
boundary and the *difference localizes the fault*.

| Observation | Conclusion |
|-------------|------------|
| drops at stage 1 | device / cable / bus bandwidth / EMI |
| stage 1 OK, drops 1→2 | uvcvideo (organization, clock, errors) |
| stage 2 OK, drops 2→3 | vb2 buffer starvation / host scheduling |
| stage 3 OK, drops 3→4 | **application too slow** (late DQBUF/QBUF) |
| FPS falls at stage 4 only | not a USB problem at all — app or display |

No existing tool (usbmon, v4l2-ctl, GStreamer stats) gives this *cross-layer*
attribution in one view. That is why this is worth building.

## Design principles (value-oriented)

1. **Instrument every stage**, then correlate. A single-stage number is data; the
   delta between stages is a diagnosis.
2. **Standalone first, then diag.** A signal appears in `usbtrace uvc` (text +
   `--json`) before it becomes a correlated diag rule.
3. **Compare against intent, not constants.** Wherever possible measure *actual
   vs negotiated/expected* (negotiated FPS, requested resolution, queued buffer
   count) instead of magic thresholds.
4. **One vertical, many layers.** Keep the wire layer on the shared
   class-traffic foundation; add new event kinds per layer rather than bloating
   one struct.
5. **Make conclusions actionable.** Every diag finding names the stage and a fix.

## Current state (stages 1–2, done)

Hook: `kprobe/uvc_video_complete(struct urb *urb)`.

| Capability | Output |
|------------|--------|
| Per-URB isoc health (status, error_count, packets, bytes) | `class_urb_event` |
| Frame reconstruction (FID/EOF) → real FPS, drops/corruption | `uvc_frame_event` |
| PTS / SCR(STC,SOF) extraction | `uvc_frame_event` |
| Per-frame bytes/packets/err_packets/duration/interval | `uvc_frame_event` |
| CLI `--fps N`, `--no-frames`, `--all`; text/JSON + summary | `uvc.c` |
| diag rules `video-frame-drops`, `video-low-fps` (+ `>=`/`<=`) | engine/rules |

Files: `src/modules/uvc/uvc.bpf.c`, `uvc.c`, `include/usbtrace/uvc.h`, diag glue
in `src/modules/diag/{diag.c,engine.*,rules.*}`.

## Phase A — deepen stages 1–2 (wire & driver, low risk)

Squeeze more truth from data already in hand. No new hooks.

- [ ] **PTS/SCR jitter as a first-class signal.** Track per-stream `pts` deltas
      (presentation cadence) and host-receive-vs-SCR skew; emit `pts_jitter_ns` /
      `scr_jitter_ns`. Catches clock drift / flaky timestamping that FPS hides.
- [ ] **Bandwidth utilization per interval.** bytes/interval vs the endpoint's
      `wMaxPacketSize × mult`; sustained ~100% with drops ⇒ bandwidth-bound.
- [ ] **Empty/zero-length packet ratio.** A spike precedes underrun (camera not
      keeping up). Cheap, additive.
- [ ] **Frame-size variance / partial frames.** Flag frames far from the running
      mean (truncated even when EOF arrived) — important for compressed formats.

## Phase B — stream context (give the numbers meaning)

Know what the stream is *supposed* to do, so "slow" means "below negotiated".

- [ ] **Negotiated format / resolution / target frame interval.** Parse UVC
      `VS_COMMIT_CONTROL` (`dwFrameInterval`, `dwMaxVideoFrameSize`,
      `dwMaxPayloadTransferSize`) by hooking the control URB and reading the
      setup + payload. **Highest-accuracy win**: turns `video-low-fps` from a
      hardcoded 15fps into "below the negotiated rate", and frame-size checks
      into "below `dwMaxVideoFrameSize`".
- [ ] **Altsetting / bandwidth (re)negotiation.** Hook `usb_set_interface`; emit
      a stream event on alt change (alt number + chosen endpoint payload).
      Alt-flapping ⇒ the camera repeatedly renegotiating ⇒ bandwidth contention.
- [ ] **Per-stream identity.** Key by `(bus,dev,iface,ep)` + a stable stream id
      so multi-stream cameras (MJPEG + YUY2 at once) are separated everywhere.

## Phase C — payload & format awareness (look inside the frame)

- [ ] **Format-aware validation.** With the format known (Phase B): MJPEG must
      start `FF D8` / end `FF D9`; uncompressed must match `w×h×bpp`. Flag frames
      that pass FID/EOF but fail content checks.
- [ ] **Still-image capture path.** Track still (`STI` bit) vs streaming frames
      separately so a still capture isn't scored as a dropped video frame.
- [ ] **Header-flag accounting.** Per-frame counts of each bmHeaderInfo bit
      (ERR/STI/EOH/SCR/PTS/EOF/FID) to surface header anomalies.

## Phase D — stage 3: videobuf2 delivery layer (the big unlock)

This is where "frames on the wire" becomes "frames the kernel handed up", and
where buffer starvation / host scheduling problems live. **This is the highest
*new* value in the whole plan** because it opens cross-layer gap analysis.

- [ ] **vb2 buffer lifecycle.** Instrument videobuf2 via its tracepoints
      (`vb2_buf_queue`, `vb2_buf_done`, `vb2_qbuf`, `vb2_dqbuf`) or kprobe
      `vb2_buffer_done(struct vb2_buffer *, state)`. Emit a `vb2_event` per
      buffer transition with `sequence`, `bytesused`, `timestamp`, `state`
      (done/error/queued), and queued-buffer depth.
- [ ] **Buffer starvation detection.** Track the count of buffers the driver
      owns vs the app owns. Driver out of free buffers when a frame arrives ⇒ the
      frame is dropped *because the app didn't return buffers fast enough* — a
      stage 3→4 problem, not a USB one. This is a conclusion users desperately
      want and nothing else reports cleanly.
- [ ] **vb2 sequence-gap = true delivered drops.** `sequence` jumps in
      `vb2_buf_done` are the authoritative "frames the kernel actually lost",
      independent of our wire-side reconstruction. Cross-check the two.
- [ ] **Wire→vb2 latency.** Time from our `uvc_frame_event` (EOF on the wire) to
      the matching `vb2_buf_done`. A growing gap ⇒ driver-side backlog.

### Phase D — implementation guide

Step-by-step plan for building stage 3. **Scope: vb2 only** — do not pull in
Phase E (`v4l2_dqbuf` / app boundary) yet. Phase D alone already enables gap
analysis against the existing wire layer:

| Comparison | Conclusion |
|------------|------------|
| wire OK, vb2 `sequence` gaps | driver/vb2 dropped frames (not USB) |
| wire drops, vb2 drops | cable / bandwidth / device |
| wire OK, vb2 OK | USB path healthy (look at Phase E for app issues) |

#### Architecture: extend `uvc`, don't fork a new module

Keep one vertical on one skeleton — same ringbuf, same `diag` registration,
shared BPF maps for wire↔vb2 correlation:

```
uvc.bpf.c
  ├─ kprobe/uvc_video_complete        → class_urb_event + uvc_frame_event  (done)
  └─ tracepoint/vb2/vb2_buf_done      → uvc_vb2_event                      (new)
```

`usbtrace_autoload_filter()` (`src/probe.c`) disables the vb2 program when the
tracepoint is absent, so stages 1–2 keep working on kernels without it.

#### Hook choice

| Priority | Hook | Why |
|----------|------|-----|
| **1 (start here)** | `tracepoint/vb2/vb2_buf_done` | Stable ABI; args are `struct vb2_buffer *` + `enum vb2_buffer_state`; carries everything needed for sequence / bytesused / drops |
| 2 (later) | `tracepoint/vb2/vb2_buf_queue` | Queue depth / starvation (needs paired accounting) |
| 3 (fallback) | kprobe `vb2_buffer_done` | Only if the tracepoint is missing on a target kernel |

Start with **one** tracepoint. It is enough for: vb2-side FPS (`interval_ns`),
authoritative drop detection (`sequence` gaps), and wire→vb2 latency (time
correlation). Add `vb2_buf_queue` in a follow-up once `vb2_buf_done` is proven.

Kernel trace format (typical):

```
TRACE_EVENT(vb2_buf_done,
    TP_PROTO(struct vb2_buffer *b, enum vb2_buffer_state state),
    TP_ARGS(b, state),
    TP_STRUCT__entry(__field(void *, buf) __field(enum vb2_buffer_state, state)),
    ...
);
```

The BPF program receives a tracepoint context whose `buf` field is the
`vb2_buffer *` pointer — CO-RE-read the fields you need from module BTF
(`videobuf2_common`).

#### Event model

Add to `include/usbtrace/common.h`:

```c
USBTRACE_EVT_UVC_VB2 = 7,   /* vb2 buffer done; see uvc.h */
```

Add to `include/usbtrace/uvc.h`:

```c
struct uvc_vb2_event {
    struct usbtrace_event_hdr hdr;   /* kind = USBTRACE_EVT_UVC_VB2 */

    __u32 sequence;        /* vb2 authoritative frame counter */
    __u32 bytesused;
    __u64 vb2_timestamp;   /* buffer timestamp (reference; interval uses ktime) */
    __u8  state;           /* VB2_BUF_STATE_DONE / ERROR / ... */
    __u32 interval_ns;     /* prev done → this done (vb2-side FPS source) */
    __u8  seq_gap;         /* 1 = sequence jumped (kernel actually lost a frame) */
    __u32 wire_to_vb2_ns;  /* set when a recent wire frame was correlated */

    __u16 vid;
    __u16 product;
    __u16 busnum;
    __u16 devnum;

    char comm[USBTRACE_COMM_LEN];
};
```

`uvc.c` routes by `hdr.kind` (same pattern as `uvc_frame_event` today). Exit
summary adds a **vb2** block alongside the existing wire/frame summary:
`vb2 frames / seq_gaps / vb2 fps / avg wire→vb2`.

Optional `uvc_config` flag: `no_vb2` (mirrors `no_frames`) to skip the module-BTF
tier on demand.

#### Module-BTF types (minimal declarations)

Do not pull in a full `videobuf2_common` BTF dump unless the verifier demands it.
Declare only the fields you read, with CO-RE markers:

```c
enum vb2_buffer_state {
    VB2_BUF_STATE_DEQUEUED = 0,
    VB2_BUF_STATE_IN_REQUEST = 1,
    VB2_BUF_STATE_PREPARING = 2,
    VB2_BUF_STATE_QUEUED = 3,
    VB2_BUF_STATE_ACTIVE = 4,
    VB2_BUF_STATE_DONE = 5,
    VB2_BUF_STATE_ERROR = 6,
};

struct vb2_buffer {
    __u32 index;
    __u32 type;
    __u32 memory;
    __u32 flags;
    __u32 sequence;
    __u32 bytesused;
    __u64 timestamp;
    /* add fields only as needed */
} __attribute__((preserve_access_index));
```

libbpf resolves these against `/sys/kernel/btf/videobuf2_common` when the module
is loaded. If CO-RE relocation fails on a field, trim the declaration or add the
field from `bpftool btf dump file /sys/kernel/btf/videobuf2_common format c`.

Keep the vb2 program in a **separate `SEC()` / function** — do not bolt it onto
`uvc_parse_frames()` (verifier budget).

#### Device filtering (hardest practical problem)

`vb2_buf_done` fires for **every** V4L2 queue (e.g. `virtual_video`, other
cameras). Must filter or the output drowns in noise.

**v1 — cheap BPF filters (ship first):**

```c
if (state != VB2_BUF_STATE_DONE)
    return 0;
if (bytesused == 0 || bytesused > MAX_REASONABLE)
    return 0;
/* optional: bytesused near negotiated frame size, e.g. 614400 for 640×480 YUYV */
```

User-space `--vid/--pid` can drop events with `vid == 0` until BPF filtering
improves. Good enough to validate the pipeline.

**v2 — BPF device identity (follow-up):**

Walk `vb2_buffer → vb2_queue → … → USB vid/pid`. Exact path is kernel-version
dependent; may need `uvcvideo` module BTF for `drv_priv`. Until then, correlate
in user space / diag by timeline with `uvc_frame` events on the same
`(bus,dev)`.

#### Wire ↔ vb2 correlation

Wire (`uvc_frame_event`) and vb2 (`uvc_vb2_event`) do **not** share a native
sequence ID. Do not block v1 on perfect frame-to-buffer pairing.

**v1 — time-window correlation (good enough for gap analysis):**

```c
/* BPF map: key = stream id (queue ptr hash or (bus,dev) once known) */
struct stream_corr {
    __u64 last_wire_done_ns;
    __u32 last_wire_bytes;
};

/* uvc_emit_frame():  last_wire_done_ns = now; last_wire_bytes = bytes; */
/* vb2_buf_done:      if (now - last_wire_done_ns < 100ms)
                       wire_to_vb2_ns = now - last_wire_done_ns; */
```

On a healthy UVC stream, wire EOF → `vb2_buf_done` is typically a few ms.
Sustained growth in `wire_to_vb2_ns` ⇒ driver-side backlog.

**v2 — stronger pairing:** match `bytesused` ≈ `uvc_frame.bytes` within the
same time window.

#### Delivery plan (four PRs, each shippable)

**PR-1 — minimal loop (do first)**

- [x] `USBTRACE_EVT_UVC_VB2` + `struct uvc_vb2_event`
- [x] `SEC("raw_tracepoint/vb2_v4l2_buf_done")` (5.15) or
      `raw_tracepoint/vb2_buf_done` (6.x) in `uvc.bpf.c`
- [x] Read `sequence`, `bytesused`, `state`; compute `interval_ns`
- [x] `uvc.c`: route, print text/JSON, basic summary; `--no-vb2` / `no_vb2`
- [ ] **Verify:** `sudo usbtrace uvc --all --vid 0x046d` with a camera streaming;
      vb2 FPS ≈ wire FPS (~15fps on a 640×480 YUYV camera); `sequence`
      monotonic.

**PR-2 — authoritative drop detection**

- [x] Per-stream BPF map `last_sequence`
- [x] Set `seq_gap = 1` when `sequence != last + 1` (handle wrap explicitly)
- [x] Summary: `vb2 frames / seq_gaps / vb2 fps (avg/worst/best)`
- [ ] **Verify:** stress the bus (high res, hub sharing) and see `seq_gap` events.

**PR-3 — wire↔vb2 gap analysis (the differentiator)**

- [ ] `stream_corr` map; fill `wire_to_vb2_ns` on vb2 events
- [ ] Exit summary compares side-by-side:
      `wire fps` vs `vb2 fps`, `wire drops` vs `vb2 seq_gaps`,
      `avg wire→vb2 latency`
- [ ] **Verify:** USB healthy + vb2 gaps ⇒ conclusion is "not a USB fault".

**PR-4 — diag integration**

- [ ] `diag.c` `normalize()` case for `USBTRACE_EVT_UVC_VB2`
- [ ] Engine fields: `vb2_sequence`, `vb2_seq_gap`, `vb2_bytesused`,
      `wire_to_vb2_ns`
- [ ] Evidence printer (like `uvc_frame`: show seq/bytes/interval/gap)
- [ ] Example rules in `rules.yaml`:

  ```yaml
  - id: video-vb2-drops
    name: "UVC vb2 sequence gaps"
    severity: warn
    trigger: { kind: uvc_vb2 }
    when:
      - kind: uvc_vb2
        match: { vb2_seq_gap: 1 }
        within_ms: 3000
        count_gte: 3
    conclusion: "Video device {vid}:{pid} lost {count} vb2 frames (sequence gaps) within {window}ms; USB wire may be fine — suspect driver queue or host scheduling."
    fix: "Check buffer count in the capturing app, CPU load, and whether other processes hold vb2 buffers."

  - id: video-wire-ok-vb2-drops
    name: "USB OK but vb2 dropping"
    severity: warn
    trigger: { kind: uvc_vb2 }
    when:
      - kind: uvc_frame
        match: { frame_errored: "!1" }
        within_ms: 3000
        count_gte: 10
      - kind: uvc_vb2
        match: { vb2_seq_gap: 1 }
        within_ms: 3000
        count_gte: 3
    conclusion: "Device {vid}:{pid}: wire frames look clean but vb2 dropped {count} frames — not a USB/cable issue."
  ```

  Cross-kind rules like `video-wire-ok-vb2-drops` are the payoff of gap analysis;
  they may need engine tweaks if multi-kind `when` is not yet expressive enough —
  ship `video-vb2-drops` first.

#### Pitfalls

| Issue | Mitigation |
|-------|------------|
| `virtual_video` / other nodes pollute output | v1: `bytesused` threshold; v2: device walk |
| Verifier complexity | Separate SEC/function for vb2; don't merge with isoc loop |
| `vb2_buffer.timestamp` unit varies by kernel | Prefer `bpf_ktime_get_ns()` for `interval_ns` |
| tracepoint absent | `usbtrace_autoload_filter` skips program; wire layer unaffected |
| CO-RE field missing on old kernel | Trim struct declaration; feature-probe + degrade |
| Perfect wire↔buffer identity | Defer to v2; time + bytesused matching is enough for v1 |

#### PR-1 verification checklist

```bash
# modules + module BTF present
lsmod | grep -E 'uvcvideo|videobuf2'
ls /sys/kernel/btf/videobuf2_common

# tracepoint present (needs root)
ls /sys/kernel/tracing/events/vb2/vb2_buf_done

# run with camera streaming (e.g. browser on /dev/video*)
sudo ./build/usbtrace uvc --all --vid 0x046d

# expect interleaved lines:
#   frame  ok  614400B ... fps=14.7 ...     ← wire (stage 1–2)
#   vb2    ok  seq=42 bytes=614400 ...     ← vb2  (stage 3)

# JSON
sudo ./build/usbtrace --json uvc --vid 0x046d | jq 'select(.event=="uvc_vb2")'
```

Success criteria for PR-1: vb2 events appear; vb2 FPS is within ~10% of wire FPS;
`sequence` increments by 1 almost always.

## Phase E — stage 4: application boundary (close the loop)

The userspace-facing edge: what the app actually experiences.

- [ ] **DQBUF/QBUF cadence = real app FPS.** Hook `v4l2_dqbuf` / `v4l2_qbuf`
      tracepoints (or the ioctl path). The interval between successive DQBUFs is
      the *application's* frame rate — the number the user actually sees, vs our
      wire FPS. Divergence isolates "USB is fine, the app/display is slow".
- [ ] **DQBUF stall / QBUF-return latency.** Time a buffer spends owned by
      userspace (`dqbuf` → next `qbuf`). Long ownership = the app is the
      bottleneck (slow consumer, blocked on encode/display).
- [ ] **Per-process attribution.** At the syscall boundary `comm`/`pid` are the
      *real* app (unlike the IRQ-context wire layer). Finally answer "which
      process is starving the camera".
- [ ] **End-to-end frame latency.** wire-EOF → vb2-done → DQBUF for the same
      `sequence`: the full glass-to-app latency, broken down by stage.

## Phase F — correlation, presentation, controller (advanced)

- [ ] **Cross-layer diag rules.** The payoff of D+E: rules like "wire OK + vb2
      starved ⇒ app not returning buffers", "wire drops + power autoresume ⇒
      suspend mid-stream", "DQBUF slow only ⇒ not a USB fault". The data already
      flows through diag; this is mostly new rules + a stage field.
- [ ] **Unified per-frame timeline.** One view tracking a frame by `sequence`
      across all four stages with per-stage timestamps — the "where did my frame
      go" table.
- [ ] **Histograms / percentiles.** Interval/jitter/latency histograms (BPF
      array map) for p50/p95/p99 at each stage instead of min/avg/max.
- [ ] **Isoc scheduling latency.** `urb->start_frame` cadence vs completion to
      separate host-scheduling gaps from device starvation.

## diag integration checklist (per new signal)

1. Add the field to the relevant event in `include/usbtrace/uvc.h` (or a new
   `uvc_*_event`); new record kinds go in `enum usbtrace_event_kind`
   (`common.h`).
2. Normalize in `src/modules/diag/diag.c` (`normalize()`) into a `diag_event`
   field (`diag.h`).
3. Add `F_<NAME>` to `enum diag_field` (`engine.h`), wire `ev_field_val()`
   (`engine.c`), add the symbol in `field_syms[]` (`rules.c`).
4. New kind: add a name in `kind_str()` (`engine.c`) + `kind_syms[]` (`rules.c`)
   and enrich the evidence printer in `print_finding()`.
5. Add a default rule to `rules.yaml`; document in [diag.md](diag.md) +
   [class.md](class.md).

DSL operators available: `=`, `!v`, `>=v`, `<=v` (see `match_one()`).

## Implementation notes (constraints, not scope limits)

These shape *how*, not *whether*. None of them remove a feature from the plan.

- **Stages 3–4 use the module-BTF tier (supported, opt-in).** `struct
  vb2_buffer`, the vb2/v4l2 tracepoints, and `videodev`/`videobuf2_common` live
  in module BTF (they are loadable modules), not `vmlinux` BTF. This is an
  explicitly allowed tier (see [class.md](class.md#vmlinux-btf-vs-module-btf-portability-tiers)),
  not a forbidden one: kernel ≥5.11 supports CO-RE against module BTF, so load it
  and degrade gracefully so a kernel without it still runs stages 1–2.
  **The graceful-degradation half already exists**:
  `usbtrace_autoload_filter()` (`src/probe.c`) feature-probes every BPF program
  before load and disables those whose hook is absent (functions via
  kallsyms/ftrace, tracepoints via tracefs), so optional stage 3–4 programs can
  ship in the same skeleton and simply stay dark where unsupported. What remains
  for stages 3–4 is the module-BTF *type* plumbing (declare the needed
  module structs with `preserve_access_index`, or load module BTF) — see
  architecture's "Graceful degradation" section.
- **Tracepoints > kprobes where they exist.** vb2/v4l2 tracepoints are a stabler
  ABI than internal functions; prefer them, kprobe as fallback.
- **Frame identity across stages.** Correlate by `sequence` (vb2/v4l2 carry it)
  and timestamp; our wire layer must learn/emit a compatible sequence to join
  stages 2↔3.
- **`comm` context differs by stage.** Wire/vb2-done run in IRQ/softirq (`comm`
  is bogus); the v4l2 syscall layer has the real process — exploit that for
  attribution in stage 4 only.
- **Verifier budget & map sizing.** Aggregate in per-stream maps over emitting
  per-packet/per-buffer floods; bump `streams`/buffer maps for many cameras.

## Suggested order (by value)

1. **Phase D (vb2)** — unlocks gap analysis, the single biggest differentiator.
2. **Phase B negotiated-format** — kills the hardcoded FPS threshold (accuracy).
3. **Phase E (app boundary)** — completes glass-to-app, adds real per-process
   attribution.
4. **Phase A** — cheap additive depth, do alongside anything.
5. **Phase F** — correlation/presentation once ≥3 stages emit data.

Phases A–C are pure `vmlinux`-BTF wire work (ship anytime). D–E are the
cross-layer leap; they cost module-BTF plumbing but deliver the conclusions that
make this tool worth choosing over everything else.
