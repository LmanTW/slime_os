# 17. Per-component energy accounting

| | |
| --- | --- |
| Route | hardware |
| Depends on | [Hardware H track](../plans/framework-hardware.md#slice-acceptance) daily-driver quality goals; the capability-matrix horizon questions whether accounting is authority or read-only telemetry (EnergyAccount row) |
| Enables | background power budgets carried as grants; battery-policy as manifest data |

## Motivation

Scheduler-attributed energy per component and per channel activity,
with policy such as background power budgets carried as grants. On a
daily-driven laptop, "which component ate the battery" is currently
unanswerable, and "this background service may not exceed a power
budget" is unenforceable. Carrying budgets as grants makes energy
policy generation data — declared, auditable, rollbackable — like every
other resource decision.

## Design sketch

Two layers with a deliberate boundary. Measurement: the scheduler
attributes active time per component, and channel activity is charged
to endpoints' owners; hardware energy counters (RAPL-class, battery
controller) convert time-and-activity into energy estimates. This layer
is telemetry — numbers, no authority.

Policy: a generation-declared budget per component (or per supervision
subtree), enforced by throttling past the budget — scheduling policy in
userspace, per the policy-free-kernel invariant. The horizon's question
is where the boundary lands: if a budget causes throttling, the
EnergyAccount is acting as authority and belongs in the rights grammar;
if it only informs a userspace policy service, it stays read-only
telemetry and out of the matrix. The register's exit condition —
throttled past its declared budget — implies the authority reading,
with the enforcement mechanism itself living in userspace policy.

## Open questions

- The horizon question itself: authority or read-only telemetry — and
  if authority, what are the rights bits?
- Attribution of shared work: a service processing another component's
  request charges whom (caller, callee, split)?
- Budget window: energy per boot, per wall-clock window, or per
  session — and how does rollback treat accumulated consumption?
- Throttling semantics: hard scheduling denial versus priority
  degradation, and who declares which per component.
