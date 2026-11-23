# 15. Zutai-defined state migrations

| | |
| --- | --- |
| Route | sync |
| Depends on | Zutai evaluation in the build pipeline (host-side is acceptable) |
| Enables | [entry 29](29-schema-state-merge.md) (merge is migration's multi-machine generalization) |

## Motivation

State schema upgrades expressed as pure Zutai transformations are
deterministic, dry-runnable before activation, and covered by the same
rollback contract as the boot graph. Today a schema change would be an
implicit, unauditable rewrite of state bytes; as Zutai transformations,
migrations become generation data — inspectable, replayable, and
reverted by the same mechanism that reverts the components reading the
state.

## Design sketch

A migration is attached to a schema version pair (v1→v2) as a pure
Zutai function from old binding bytes to new binding bytes. Pure means:
no clock, no entropy, no I/O — the same determinism discipline
[D3 deterministic-component authority](../plans/native-development.md#deterministic-component-authority) defines, enforced here
by the evaluator rather than by grants.

Dry-run: the builder (or a host tool) applies the migration to a fixture
binding — or to a snapshot of real state — and reports the result
without sealing it, so a generation author sees the migrated state
before activation. Apply: during activation, the pending generation's
declared migrations run against the snapshotted bindings; the migrated
result seals as a new object in the new epoch. Rollback restores the
pre-migration binding per policy, which M5.6b's reachability already
guarantees is retained.

Failure semantics: a migration that errors or fails validation leaves
the old epoch intact and the pending generation fails health — the same
failure accounting as any other activation fault.

## Open questions

- Who writes the v1→v2 transform — the component author shipping the new
  schema (and how is it reviewed), or the generation author?
- Dry-run reporting shape: diff of decoded state, or just success/failure
  plus the result hash?
- Migration chains (v1→v3 through v2): composed automatically, or must
  each adjacent pair be declared?
- Validation: does the migrated output get checked against the v2 schema
  structurally before sealing?
