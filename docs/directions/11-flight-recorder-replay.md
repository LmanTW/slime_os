# 11. IPC flight recorder and deterministic replay

| | |
| --- | --- |
| Route | determinism |
| Depends on | replay of arbitrary components additionally wants [D3 deterministic-component authority](../plans/native-development.md#deterministic-component-authority) |
| Enables | [entry 26](26-hermetic-testing.md); failure reports as generation hash + trace |

## Motivation

All component input crosses channel boundaries, so recording at that
boundary yields deterministic re-execution of a single component. A bug
report becomes a generation hash plus an IPC trace: the reporter's exact
component bytes (content-addressed by the generation) and exact inputs
(the trace) are both in the report, so the failure is reproducible by
anyone, anywhere, without the reporter's machine.

For agent components this is the audit primitive: what the agent did is
what crossed its channels, and a trace is the complete, checkable record.

## Design sketch

Two halves with separate blockers. Recording: generalize the M5.3
recorder into the entry-7 membrane so any endpoint's traffic can be
captured in a bounded canonical trace format, sealed as an object. This
half is legal today and its format design should be co-designed with
entry 7.

Replay: a harness that instantiates the component from the named
generation with a virtual channel set, feeds the trace, and compares
output byte-for-byte. For components declared deterministic under
D3's authority rule, replay needs no undeclared nondeterminism input. For others,
the trace must additionally capture every nondeterminism draw (clock reads,
entropy); D3 retains the seeded-stream option for reproducible entropy.

Replay scope is deliberately per-component, not whole-system: the
component is the determinism boundary, peers are replaced by the trace.
Whole-graph replay is not a goal of this entry.

## Open questions

- Trace format: per-endpoint streams or a single causally ordered log?
  (The former composes with per-component replay; the latter with
  multi-component analysis.)
- How are large payloads represented — inline (bounded, heavy) or as
  content-addressed object references into the M5.4 store?
- For non-deterministic components, is trace-captured nondeterminism
  sufficient, or must replay refuse components lacking D3 deterministic-component
  declarations?
- Where does replay run — host-side against the same component bytes, or
  under QEMU as a test target like `storage_fault_check`?
