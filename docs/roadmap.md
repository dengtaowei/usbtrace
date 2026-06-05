# usbtrace roadmap & expansion requirements

Concrete realization of req #3 (extensibility: beyond core USB debugging, also
support USB class subsystems such as UAC/UVC). Each item is a self-contained
module (see `docs/modules.md` for the authoring contract).

## Phase 0 — foundation (done)

- [x] Modular core + registry, ring-buffer event envelope (`usbtrace_event_hdr`)
- [x] Multi-arch build (x86/x86_64/arm/arm64) + cross-compile
- [x] `urb` module: submit/complete + latency, per-device filter

## Phase 1 — core USB diagnosis (highest BSP value)

- [ ] `enum` — enumeration timeline: `usb_alloc_dev`, `usb_set_device_state`,
      `hub_port_*`, control GET_DESCRIPTOR/SET_ADDRESS/SET_CONFIG; flag where it
      stalls/fails. (Fallback to kprobes when tracepoints absent.)
- [ ] `lifecycle` — connect/disconnect/reset & re-enumeration root cause;
      correlate `usb_disconnect` with preceding URB errors.
- [ ] `power` — autosuspend/runtime-resume vs URB activity; resume-fail,
      remote-wakeup issues.
- [ ] `diag` mode — nettrace-style rule engine across modules (e.g. "disconnect
      preceded by N bulk errors → suspect link/power"). Output: conclusion +
      evidence chain, not raw dumps.

## Phase 2 — class subsystems (req #3 explicit targets)

- [ ] `uac` — USB Audio Class: isoc URB scheduling, underrun/overrun, sample
      rate/feedback endpoint health (snd-usb-audio paths).
- [ ] `uvc` — USB Video Class: frame drops, bandwidth/altsetting, isoc errors
      (uvcvideo paths).
- [ ] `hid` — report flow & latency (`hid_input_report`, interrupt URBs);
      surface unexpected SET_REPORT (BadUSB-style).
- [ ] `storage` — Bulk-Only Transport / UAS: CBW/CSW decode, SCSI errors,
      stall/reset recovery.

## Phase 3 — controller & device side (advanced)

- [ ] `hcd` — xhci/dwc3 ring + port state machine (expert view).
- [ ] `gadget` — device-side UDC request lifecycle (`usb_ep_queue`,
      `usb_gadget_giveback_request`, `usb_gadget_set_state`); OTG/DRD role switch.

## Cross-cutting requirements

- **Output formats**: keep human-readable default; add `--json` for tooling and
  a future TUI/canvas. All modules share the event-header envelope so a single
  consumer/exporter can serve every module.
- **Filtering**: standardize common filters across modules (`--vid/--pid`,
  bus-port path, pid/comm, devnum) — factor into a shared helper when the 2nd
  filtering module lands.
- **Symbolization & stacks**: optional kernel stack capture for error paths
  (gated, off by default for low overhead).
- **CO-RE robustness**: feature-probe optional kfuncs/tracepoints; degrade
  gracefully on older kernels rather than failing to load.
- **Packaging**: prebuilt static binaries per arch; optional committed
  `bpf/vmlinux/<arch>/vmlinux.h` for reproducible cross/CI builds.
- **Tests/CI**: smoke-load every module's skeleton in a VM matrix across the
  supported arches and a range of kernels.
