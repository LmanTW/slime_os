# Plans

This directory owns unimplemented designs, delivery requirements, and
qualification requirements that are specific enough to guide future work but do
not describe current behavior.

Plans are not a tracker. Identity, state, priority, hierarchy, dependencies, and
observed exit conditions live only in `.tasks/items/` and on the `evidence`
branch; `specs/legacy.zt` indexes the V1 items. A plan names canonical
work-item UUIDs when work exists; editing a plan never creates, starts, closes,
or reorders an item.

Keep current architecture, operation, and limitations in the owning product or
contract documentation. Keep important accepted or proposed cross-module choices
in `docs/decisions/`, with explicit status and revisit conditions. Keep
exploratory possibilities that are not committed work in `docs/directions/`.
Delivery chronology and historical verification results do not belong in a plan.

## Designs

- [System-image closures as derivations](system-image-closure-derivations.md) — closures that
  commit sources instead of in-tree digests, and attestations of outputs in git notes.

## Qualification designs

- [Console record qualification](console-record-qualification.md) — deterministic
  root/console contention, whole producer operations, and retained local QEMU regressions.

## Extracted requirements

- [Memory capacity](memory-capacity.md) — target-bound multi-holder capacity
  and reclamation qualification beyond the existing memory mechanism.
- [Network data plane](network-data-plane.md) — real TCP bytes over LinkDevice,
  exact destination authority, and bounded reset/restart behavior.
- [Framework hardware](framework-hardware.md) — device qualification after
  CPU boot, IOMMU containment, recovery, and the internal-storage safety boundary.
- [Authority and trust](authority-and-trust.md) — revocation, secrets,
  accelerator authority, attestation, and distributed capabilities.
- [RPi5 ROS 2 demo](rpi5-ros2-demo.md) — bounded middleware interoperability
  and the exact physical-board evidence boundary.
- [Architecture releases](architecture-releases.md) — exact-target RV64 Milk-V
  Duo and AArch64 release composition and evidence limits.
- [ROS 2 wire compatibility](ros2-wire-compatibility.md) — minimum topics,
  external peers, services/actions, and the transport-security boundary.
- [Existing workloads](existing-workload.md) — backend admission for each
  workload's exact target profile.
- [Foreign workloads](foreign-workloads.md) — the X1 Linux userspace personality
  and the X2 AMD-V guest.
- [Native development](native-development.md) — D1–D7: in-system authoring,
  hermetic build, ephemeral admission, live cutover, and on-device generations.
- [M5 and M6 retained requirements](foundations-m5-m6.md) — M5.7 Framework NVMe
  promotion, and M5 and M6 checks not confirmed against a gate.
- [I/O substrate retained requirements](io-substrate-qualification.md) — IO2 and
  IO3 evidence their gates do not establish.

The former `roadmap/` files are retired. The pages above own their open
requirements. Historical investigations are preserved in the [archive](../history.md).
