# Architecture

Current subsystem ownership, boundaries, invariants, and limitations. These pages
explain the product as it exists now; they do not carry work-item state or
historical delivery chronology.

Every behavior claim points to the implementation, Zutai contract, reference
document, or executable gate that owns it. `.tasks/items/` remains the only live
store for scope, state, relationships, and observed exit conditions.

## Core runtime

- [IPC and capability movement](ipc-and-capabilities.md) — native endpoints,
  root-served mechanism calls, bounded messages, transfer, and shared buffers.
- [Typed data fabric](typed-data-fabric.md) — graph authority, stream/call/
  operation policy, QoS, recording, and current bounds.
- [Time, waiting, scheduling, and lifecycle](runtime-authority.md) — clock
  authority, userspace wait sets, priority classes, supervised restart, and the
  CPU-budget boundary.
- [Private component memory](private-memory.md) — fixed-base growth, target-bound
  budgets, userspace allocation, reclamation, and capacity qualification.

## Product-wide boundaries

- [Component, system, and image boundaries](component-system-image.md) — what a
  component spec, system spec, generation, image closure, and test run each own.
- [Architecture and target profiles](targets-and-portability.md) — portable
  semantics versus platform mechanism, admitted targets, evidence scope, and
  target-specific limitations.
- [Userspace I/O substrate](io-substrate.md) — queue/epoch/lease semantics,
  hardware authority, and userspace drivers.
- [Network service](network-service.md) — destination authority, external and
  loopback smoltcp backends, bounded TCP streams, lifetime and reset behavior,
  and the bounded HTTP/DNS client.
- [Zenoh Profile 0 transport](zenoh-transport.md) — the bounded Zenoh wire
  codec, session machine, byte-stream runtime and the two demo nodes on
  `sel4-zenoh`, with what is and is not observed.
- [Generation management](generation-management.md) — BootState, the
  pre-admission boot selector, the userspace manager protocol, rollback,
  recovery, and transfer planes, and what is not yet rollbackable.
- [Trust model](trust-model.md) — the trusted computing base, what each
  boundary enforces, and the explicit list of what is not enforced today.

## Load-bearing references

- [`../capability-matrix.md`](../capability-matrix.md) owns capability kinds,
  rights, gates, and hard resource bounds.
- [`../syscall-abi.md`](../syscall-abi.md) owns operation labels, packing, reply
  conventions, errors, and CSpace layout.
- `contracts/` owns every persisted or cross-process format.
- `AGENTS.md` maps implementation work to canonical source owners and narrow
  verification gates.

[Plans](../plans/README.md) own unimplemented requirements. Historical investigations are preserved
in the [private archive](../history.md), never required by product checks.
