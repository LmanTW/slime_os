# Image attestation format 1

An image attestation records the images one host class built from one commit. `schema.zt` is the
normative layout and lists the rules every writer and judge enforce beyond the types.

## Where attestations live

Each attestation is the body of the git note on its commit under `refs/notes/image-attestations`, as the
record's `.zti` text. No pull request diff carries one. A clone fetches the notes only when asked to:

```sh
git fetch origin 'refs/notes/image-attestations:refs/notes/image-attestations'
```

## What an attestation proves

Two entries with the same `derivationId` and the same host class must carry the same five output
digests, whichever commits they are attached to. An attestation proves bytes across commits within one
host class. It proves nothing about a boot. Entries of different host classes are never compared.

| Field | Meaning |
| --- | --- |
| `commit` | the commit the note is attached to |
| `hostClass.devShell` | the Nix store path of the default devShell derivation the build ran in |
| `hostClass.architecture` | `uname -m` on the build machine |
| `runner` | the build machine image; informational, not part of the host class |
| `images` | one entry per attested closure, sorted by `name` |

Each image entry holds the closure's name, its derivation id and the SHA-256 of the clean build's
`generation.bin`, `root.elf`, `loader.elf`, `image.elf` and `image.identity.json`. A dirty build is
never attested.

## Writer and judge

Work item `01a19619-7518-7e31-b7d0-e7c8a9edcce3` implements the writer,
`scripts/build/attest-system-images.py`, and the workflow that runs it nightly. `just image_attestation_check`
judges both. The design is in
[`docs/plans/system-image-closure-derivations.md`](../../../docs/plans/system-image-closure-derivations.md).

## Compatibility

A new field, a new output digest or a change to the host class is a new format version.
