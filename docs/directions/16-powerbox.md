# 16. Powerbox UI

| | |
| --- | --- |
| Route | lifecycle |
| Depends on | [Hardware H8](../plans/framework-hardware.md#slice-acceptance) supplies display/compositor/input for a graphical chooser |
| Enables | user-driven authority granting without ambient access; graphical and non-file generalizations beyond M6.6 |

## Motivation

Applications never hold an ambient "open file" right; the file dialog is
a system component, and the user's selection gesture itself mints a
single-object capability. Authorization and intent are the same gesture:
the user cannot approve what they did not mean, and the application
cannot receive more than the selected object. This replaces the ambient
home-directory access conventional systems grant every application.

For agent components the pattern generalizes naturally: an agent
requesting access to an object it was not granted triggers the same
chooser, and the user's gesture is the audit record.

## Design sketch

The chooser is a system component holding directory authority the
requesting component lacks. Protocol: the requester uses its declared direct
endpoint to ask the chooser for an object (kind, rights, purpose string); the
chooser renders the selection; the user's gesture mints a single-object
capability — derived from the chooser's own grant, narrowed to exactly
the selected object and the declared rights — delegated back with the typed
reply. The requesting component ends up with a capability it could
not have obtained from the manifest or any peer.

The minted capability is a narrow-only derive, so the pattern fits the
[rights algebra](../architecture/ipc-and-capabilities.md#checked-rights-algebra) without
amendment — unless the Directory question resolves otherwise, which is
why the horizon tracks it.

The general pattern beyond files: any authority whose granting requires
human intent (camera, network destination once
[entry 18](18-network-authority.md) exists) is a powerbox candidate.
The entry's design output should name what is common — the request
schema, the purpose string, the minted single-object grant — and what is
per-domain.

Audit: the gesture is a provenance event; combined with the M5.1
provenance follow-up, "why does this component have this file" has an
explicit answer rooted in a user gesture.

## Open questions

- The horizon's question: does powerbox minting need more than
  `derive` (e.g., minting a capability for an object the chooser can
  list but has not opened)?
- Persistence: is a powerbox grant per-session, or may the generation
  declare it persistent across reboots (and with what rollback
  semantics)?
- Can the chooser itself be interposed ([entry 7](07-schema-interposition.md))
  for dry-runs, or is user-intent minting excluded from membranes?
- Purpose strings: free text, or a declared vocabulary the manifest
  constrains?
