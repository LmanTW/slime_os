# 26. Hermetic generation testing

| | |
| --- | --- |
| Route | determinism |
| Depends on | [D3 deterministic-component authority](../plans/native-development.md#deterministic-component-authority) (capability-matrix amendment for clock/entropy objects) |
| Enables | flake-free rollback/health CI; completes QEMU's tier-0 role as the deterministic verification platform |

## Motivation

[D3 deterministic-component authority](../plans/native-development.md#deterministic-component-authority)
is promoted work; [entry 11](11-flight-recorder-replay.md) remains parked. Their
composition is the payoff: a test generation binds clock and entropy to
virtual fixtures so the full boot-and-health-check run is
byte-deterministic in CI. Flaky rollback and health scenarios become
impossible — a health timeout fires because the fixture clock advanced
past the declared deadline, not because CI was slow that day.

## Design sketch

A test generation is a normal generation whose manifest binds the
fixture implementations: a virtual clock object advanced by the test
harness, a seeded entropy stream. Because fixture and hardware implement
the same rights (D3's authority design), the components under test are
identical bytes — only the manifest wiring differs, and that difference
is itself auditable manifest data.

Determinism claim: two CI runs of the same test generation produce
byte-identical console and health-transition traces. This requires the
fixture clock to drive everything the health path observes — timeouts,
attempt deadlines — so the harness, not wall time, decides when the
pending generation is declared failed. QEMU remains the platform; the
claim is about the software stack inside it.

Residual nondeterminism lives below the rights line: timer IRQ timing,
scheduler interleaving. The entry's scope decision is whether
IPC-order determinism suffices (components observe the same message
sequence) or whether instruction-level determinism is claimed. The
former is the pragmatic target; the latter belongs to a different
project.

## Open questions

- Which health scenarios genuinely need fixture time — attempt
  consumption is durable-state driven, but health timeouts are
  wall-clock driven today [INFERENCE: from the timeout's role in M5.6
  fault classification].
- Does the fixture clock need a capability of its own (who may advance
  time — the harness only)?
- Console trace as the determinism oracle: is the serial log stable
  enough to be the compared artifact, or should the health-transition
  trace be a structured object instead?
