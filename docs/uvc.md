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

- **Stages 3–4 need module/extra BTF.** `struct vb2_buffer`, the vb2/v4l2
  tracepoints, and `videodev`/`videobuf2_common` live in module BTF (they are
  loadable modules), not `vmlinux` BTF. Kernel ≥5.11 supports CO-RE against
  module BTF; load that BTF explicitly and degrade gracefully so a kernel without
  it still runs stages 1–2. **The graceful-degradation half already exists**:
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
