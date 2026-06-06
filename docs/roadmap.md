# usbtrace roadmap & expansion requirements

Concrete realization of req #3 (extensibility: beyond core USB debugging, also
support USB class subsystems such as UAC/UVC). Each item is a self-contained
module (see `docs/modules.md` for the authoring contract).

## Strategic priorities (opinionated, what is most worth doing next)

The foundation (modular core, CO-RE, CI, commit policy) is solid. The items
below are ordered by impact on whether the project earns trust and adoption,
not by where they sit in the phase plan. Layered: first earn credibility, then
deliver the requirements already promised, then build the differentiator.

### Tier 0 — establish credibility (cheap, highest trust impact)

- [x] **Fix `urb` status data correctness.** Completion events used to report
      `st=-115` (`-EINPROGRESS`) for everything, which silently undermined the
      whole tool. Root cause was the hook point: `__usb_hcd_giveback_urb(urb)`
      sees `urb->status` before the final value lands. Fixed by hooking
      `usb_hcd_giveback_urb(hcd, urb, status)` and reading the `status` arg
      directly. Verified: status now reports `0`/`-32`/`-71`/`-2` etc.
- [ ] **Graceful degradation / feature probing** (also under Cross-cutting:
      CO-RE robustness). A missing kprobe target must skip+warn, not fail the
      whole load. This is the real payoff of "one CO-RE binary across kernels".

### Tier 1 — deliver requirements that are stated but not truly met

- [ ] **Cross-arch that actually builds + is verified** (req #5:
      arm32/arm64/x86/x64). The documented cross build currently fails on stock
      toolchains: libbpf's sub-make uses `$(CROSS_COMPILE)cc` (only `-gcc`
      exists), and arm64 BPF needs an arm64 `vmlinux.h` (kprobe `PT_REGS_*`
      references `struct user_pt_regs`). Fix the `cc` issue, commit per-arch
      `bpf/vmlinux/<arch>/vmlinux.h`, then re-add the cross job to CI.
- [ ] **Runtime load testing in a VM matrix.** CI today only proves it compiles,
      not that it loads/attaches. Borrow `third_party/libbpf/.github/actions/
      vmtest` to `sudo ./usbtrace <mod>` across kernels/arches. "Passes the
      verifier" is the real test for a CO-RE tool.

### Tier 2 — the differentiator (why this over usbmon/trace-cmd)

- [x] **`diag` rule engine** (also in Phase 1). nettrace's value is conclusions +
      evidence chains, not raw dumps. Implemented as a cross-module consumer
      (`src/modules/diag/`) driven by a YAML knowledge base; reuses the existing
      probes, correlates per device, and emits conclusions + evidence live with a
      summary at exit. See [diag.md](diag.md). TODO: more rules; deadline-rule
      coverage for hub_port resets; per-rule tunables.
- [x] **Cross-module correlation / unified timeline.** `diag` loads
      enum+urb+lifecycle+power together and merges their ring buffers into one
      poll loop, normalizing every record (`hdr.kind`-routed) onto a per-device
      (bus-dev-vid-pid) timeline. TODO: expose the merged timeline as a
      standalone view too (not just rule findings).

### Tier 3 — breadth (req #3 explicit targets)

- [x] Class subsystems `uac`/`uvc`/`hid`/`storage` — implemented on a shared
      class-traffic foundation (core-type URB-completion hooks) that also feeds
      `diag`. (See Phase 2 and [class.md](class.md).)

### Tier 4 — make it adoptable

- [ ] **Release & packaging**: prebuilt static binaries per arch + semver tags +
      GitHub Releases. BSP engineers want "drop one binary on the target". The
      repo has no tags yet (`VERSION` comes from `git describe`).
- [ ] **Stabilize the `--json` schema**: fix fields, add `ts_ns`/wall-clock,
      document it as a contract since downstream tooling depends on it.
- [ ] **Richer filters**: bus-port path, `comm`/pid, devnum, plus
      `--duration/--count/-o file`.

### Governance (low cost, long-term payoff)

- [ ] Lightweight unit tests for pure user-space helpers (`usbtrace_json_escape`,
      `check-commits.sh`).
- [ ] CHANGELOG + semver tags, auto-generated from the Conventional Commits
      history.

**If only three things get done next:** (1) fix the status bug, (2) real
multi-arch + VM load testing, (3) the `diag` rule engine. The first two answer
"why trust it", the third answers "why use it instead of usbmon/trace-cmd".

## Phase 0 — foundation (done)

- [x] Modular core + registry, ring-buffer event envelope (`usbtrace_event_hdr`)
- [x] Multi-arch build (x86/x86_64/arm/arm64) + cross-compile
- [x] `urb` module: submit/complete + latency, per-device filter

## Phase 1 — core USB diagnosis (highest BSP value)

- [x] `enum` (demo) — enumeration timeline via kprobe `usb_set_device_state`:
      emits each `old → new` state transition (NOTATTACHED → ... → CONFIGURED),
      so a stall/failure is visible as "stuck before ADDRESS/CONFIGURED".
      TODO: also fold in `hub_port_*` and control GET_DESCRIPTOR/SET_ADDRESS.
- [x] `lifecycle` (demo) — connect/disconnect via kprobe `usb_new_device` /
      `usb_disconnect`. TODO: reset tracking + correlate `usb_disconnect` with
      preceding URB errors.
- [x] `power` (demo) — autosuspend/autoresume via kprobe
      `usb_autosuspend_device` / `usb_autoresume_device`. TODO: correlate with
      URB activity; resume-fail and remote-wakeup issues.
- [x] `diag` mode — nettrace-style rule engine across modules (e.g. "disconnect
      preceded by N bulk errors → suspect link/power"). Output: conclusion +
      evidence chain, not raw dumps. YAML knowledge base, live + summary; see
      [diag.md](diag.md).

## Phase 2 — class subsystems (req #3 explicit targets)

All four class modules below share one foundation (`include/usbtrace/class*.h`,
`src/class_stream.c`) hooking each driver's URB-completion callback with
core-type args only (no module BTF), one normalized `class_urb_event`, and they
all feed `diag` via a table-driven source registry. See [class.md](class.md).

- [x] `uac` — USB Audio Class: isoc URB health (status, error_count, bytes,
      capture/playback) via kprobe `snd_complete_urb`. TODO: feedback-endpoint /
      sample-rate health, explicit xrun correlation.
- [x] `uvc` — USB Video Class: streaming-URB health (status, isoc error_count,
      packets/bytes) via kprobe `uvc_video_complete`. TODO: altsetting/bandwidth
      via `usb_set_interface`, per-stream frame-drop accounting.
- [x] `hid` — report flow via kprobe `hid_irq_in`/`hid_irq_out` (in/out, errors;
      OUT = SET_REPORT). TODO: decode report IDs, flag unexpected SET_REPORT
      (BadUSB-style).
- [x] `storage` — Bulk-Only Transport via kprobe `usb_stor_blocking_completion`
      (stall/timeout signals). TODO: CBW/CSW decode, SCSI sense, UAS driver path.

## Phase 3 — controller & device side (advanced)

- [ ] `hcd` — xhci/dwc3 ring + port state machine (expert view).
- [ ] `gadget` — device-side UDC request lifecycle (`usb_ep_queue`,
      `usb_gadget_giveback_request`, `usb_gadget_set_state`); OTG/DRD role switch.

## Cross-cutting requirements

- **Output formats**: [x] human-readable default + global `--json` (one JSON
  object per event line) implemented across all modules via shared helpers in
  `usbtrace/cli.h`. TODO: a single unified exporter (today each module emits its
  own fields) and a future TUI/canvas consumer.
- **Filtering**: [x] common `--vid/--pid` factored into shared helpers —
  user-space `usbtrace_filter` + `USBTRACE_FILTER_LONGOPTS` /
  `usbtrace_filter_getopt()` (`usbtrace/cli.h`) and BPF-side
  `usbtrace_dev_match()` (`usbtrace/filter.bpf.h`). TODO: bus-port path,
  pid/comm, devnum filters.
- **Symbolization & stacks**: optional kernel stack capture for error paths
  (gated, off by default for low overhead).
- **CO-RE robustness**: feature-probe optional kfuncs/tracepoints; degrade
  gracefully on older kernels rather than failing to load.
- **Packaging**: prebuilt static binaries per arch; optional committed
  `bpf/vmlinux/<arch>/vmlinux.h` for reproducible cross/CI builds.
- **Tests/CI**: smoke-load every module's skeleton in a VM matrix across the
  supported arches and a range of kernels.
