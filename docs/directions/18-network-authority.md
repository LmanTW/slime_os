# 18. Per-destination network authority

| | |
| --- | --- |
| Route | hardware |
| Depends on | [Hardware H6 networking](../plans/framework-hardware.md#slice-acceptance); the capability-matrix horizon tracks the NetworkDestination object shape |
| Enables | manifest-auditable exfiltration surface — particularly for agent components |

## Motivation

Network access is a capability to explicit endpoints declared by the
generation, making the exfiltration surface auditable in the manifest.
This is the agent-safety network story: an agent component's reachable
destinations are enumerated in the same document as every other grant,
so "where can this agent send data" is a static question with a
checkable answer — not a property of runtime socket calls.

## Design sketch

A NetworkDestination object identifies a declared remote — the
horizon's candidate shape is (protocol, address, port) — and rights
split CONNECT / SEND / RECV / LISTEN so, e.g., a component may receive
from a destination without initiating toward it. The generation
manifest lists every reachable destination per component; wildcards are
the design pressure point (an update-check destination is a stable
endpoint, but model-provider endpoints change), and each wildcard form
weakens the audit story proportionally.

Enforcement mirrors the block device: the network service is a
userspace component, and the kernel gates creation of channel endpoints
to it — a component without the destination capability cannot address
traffic there. DNS is a destination too (resolution is itself an
information flow), so the amendment must decide whether name resolution
is a separate object kind.

Audit composition: entries [9](09-grant-graph-introspection.md) and
[1](01-authority-diff-gate.md) extend for free — destination changes
across generations appear in the authority diff, and exfiltration
reachability is a query.

## Open questions

- Wildcards: are patterns (domain suffixes, port ranges) expressible,
  and how are they audited — expanded at build time or carried as
  pattern grants?
- Is DNS resolution a distinct object kind with its own rights?
- Inbound authority: does LISTEN on a declared local endpoint follow
  the same object shape, and who declares exposure?
- Per-destination budgets (rate, byte counts) — inside this row, or
  deferred to [entry 25](25-resource-accounts.md)-style accounts?
