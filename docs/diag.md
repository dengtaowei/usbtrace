# diag — USB diagnosis rule engine

`diag` is usbtrace's differentiator: instead of dumping raw events, it loads the
`urb`, `enum`, `lifecycle`, and `power` probes **together**, merges their event
streams per device, and runs a YAML-driven rule engine that emits **conclusions
+ evidence chains** (nettrace-style), live and as an end-of-session summary.

```bash
sudo usbtrace diag                              # built-in knowledge base
sudo usbtrace diag --vid 0x0403                 # focus one device
sudo usbtrace diag --rules ./rules.yaml         # custom knowledge base
sudo usbtrace --json diag | jq                  # machine-readable findings
```

## How it works

```
urb/enum/lifecycle/power skeletons (reused, no new BPF)
        │  one ring_buffer poll loop (ring_buffer__add)
        ▼
normalized struct diag_event  (routed by hdr.kind)
        ▼
per-device sliding window  (key = bus,dev; time + capacity bounded)
        ▼
rule engine ── live findings (conclusion + evidence)
            └─ summary at exit
```

- A missing kprobe target on some kernel only warns and is skipped; diag keeps
  running with whatever probes attached (graceful degradation).
- The engine is fed a normalized, kind-agnostic `struct diag_event`, so rules
  reference field names rather than per-module struct layouts.
- Devices are correlated by `(bus,dev)` only: vid/pid read `0000:0000` during
  early enumeration (before the device descriptor is fetched), so they are
  learned and attached to the window for display rather than used as the key.
- Findings are de-duplicated per `(device, rule)` with a short cooldown so a
  storm of events does not spam the output.

## Knowledge base

Rules are loaded from (in priority order):

1. `--rules <path>` — an external YAML file (edit without recompiling).
2. the **built-in** default knowledge base, embedded at build time from
   [`src/modules/diag/rules.yaml`](../src/modules/diag/rules.yaml).

### Rule schema

```yaml
rules:
  - id: disconnect-after-errors        # required, unique
    name: "Human readable name"
    severity: error                    # info | warn | error
    trigger: { kind: lifecycle, action: disconnect }
    when:
      - kind: urb
        match: { is_submit: 0 }
        status_in: [-71, -84, -110, -32, -19]
        within_ms: 2000
        count_gte: 3
    conclusion: "Device {vid}:{pid} disconnected after {count} errors in {window}ms."
    fix: "Check cable / power / port."
```

Two rule types:

| Type | Shape | Fires when |
|------|-------|------------|
| event | `trigger` + `when` list | the trigger event arrives and every `when` lookback condition is satisfied over the device window |
| deadline | `deadline` block | a device reached `reached_state` but not `without_state` within `timeout_ms` (checked on a periodic tick) |

Deadline example:

```yaml
  - id: enum-stall
    severity: error
    deadline:
      kind: enum
      reached_state: ADDRESS
      without_state: CONFIGURED
      timeout_ms: 3000
    conclusion: "Device {vid}:{pid} reached ADDRESS but never CONFIGURED within {window}ms."
    fix: "Check descriptor fetch / SET_CONFIGURATION."
```

### Lookback condition fields

| Field | Meaning |
|-------|---------|
| `kind` | `urb` \| `enum` \| `power` \| `lifecycle` |
| `match` | `{ field: value, ... }` equality on event fields; prefix the value with `!` for not-equal, e.g. `xfer_type: "!2"` |
| `status_in` | list; `urb` status is one of these (use negative errnos) |
| `within_ms` | only consider events within N ms before the trigger |
| `count_gte` | require at least N matching events (default 1) |

### Event fields (usable in `match` / `trigger`)

`kind`, `is_submit`, `status`, `xfer_type`, `dir_in`, `ep`, `action`,
`old_state`, `new_state`, `latency_ns`, `actual`, `length`.

Values may be numeric (`0`, `-71`, `0x6001`) or symbolic:

- kinds: `urb` `enum` `power` `lifecycle`
- actions: `connect` `disconnect` (lifecycle), `autosuspend` `autoresume` (power)
- states: `NOTATTACHED` `ATTACHED` `POWERED` `RECONNECTING` `UNAUTHED`
  `DEFAULT` `ADDRESS` `CONFIGURED` `SUSPENDED`

### Template variables

Usable in `conclusion` / `fix`: `{vid}` `{pid}` `{bus}` `{dev}` `{count}`
`{window}` `{comm}`.

## Built-in rules

| id | severity | catches |
|----|----------|---------|
| `disconnect-after-errors` | error | disconnect preceded by repeated transfer errors → cable/link/power |
| `autosuspend-mid-transfer` | warn | runtime autosuspend while data URBs are active → stalls |
| `resume-storm` | warn | repeated autoresume in a short window → power thrashing |
| `enum-stall` | error | stuck at ADDRESS, never CONFIGURED → enumeration failure |

## Output

Text (default):

```
[DIAG] error disconnect-after-errors 0403:6001 bus1-dev5
  conclusion: Device 0403:6001 (bus1-dev5) disconnected after 3 transfer errors within 2000ms; suspect cable/link/power.
  fix:        Check cable/connector and port power budget, reseat the device, try another port, and rule out EMI.
  evidence:
      -0.300s urb complete ep1 IN status=-71
      -0.500s urb complete ep1 IN status=-71
      -0.700s urb complete ep1 IN status=-71
```

JSON (`--json`): one object per finding plus a `diag_summary` object at exit,
e.g. `{"event":"diag","severity":"error","rule":"disconnect-after-errors",...}`.

## Extending

Copy `rules.yaml`, add a rule, and run `sudo usbtrace diag --rules ./my.yaml`.
No rebuild needed. To change the built-in defaults, edit
`src/modules/diag/rules.yaml` and rebuild (it is re-embedded automatically).
