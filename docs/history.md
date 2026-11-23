# Development history and evidence

Current architecture, operation and limitations remain in this product repository.
`.tasks/items/` is the only live work-state store, and `specs/legacy.zt`
indexes the V1 work items. Historical investigations and
large raw captures are preserved in a private repository, not a build, test,
submodule or documentation-check dependency.

## Immutable lookup

Repository identity:
`ssh://git@git.justaslime.dev:2222/iceice666/slime_os-history.git`

Product archive anchor: `45ed1745907b2d0a13fdf70c8b34eb635bed5f23`.
Tree: `e2e84b2fca59ed5221b0084aeb986dced4aeadae`.

Use repository identity + full commit + original path. For example, the
[original devlog navigation](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/45ed1745907b2d0a13fdf70c8b34eb635bed5f23/devlog/README.md)
retains its original surrounding source tree and links. Do not use mutable main
for an evidence locator. Access requires permission to the private archive;
product checks never fetch it or treat host availability as evidence.

[Archive restoration and inventory](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/e3aa4d42d87453b78286d9f6035f1b296f598811/README.md)
explain the daily branch, immutable snapshot tags, independent backup and limits.
The daily branch contains no product workflows or live task store. The owner
confirmed private visibility and disabled automation and authorized preservation
of personal/device metadata. No live secret was identified by targeted review;
this is not an exhaustive secret-absence guarantee. Do not broaden access.

## What moved and what remains

All 491 historical devlog files and the frozen backlog index were verified
against the archive before removal. The snapshot also preserves the retired
foundation and port deliveries, component-platform migration records, and
I/O driver/proof investigations. [Plans](plans/README.md) own the
requirements the product still carries.

The [archived release record](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/45ed1745907b2d0a13fdf70c8b34eb635bed5f23/roadmap/README.md#x86-64-framework-cpuproduct-boot-release) preserves the observed P6.1–P6.6 Framework CPU/product boot completion.

Promoted directions 2, 3, 5, 10, 23, 24, 28, 30, 31, and 33 are archive
lookups rather than full exploratory pages. Their current owners are:

- [native development](plans/native-development.md) for deterministic
  components, build provenance and on-device build requirements;
- [checked rights algebra](architecture/ipc-and-capabilities.md#checked-rights-algebra)
  for the current model boundary and vocabulary discipline;
- [authority and trust](plans/authority-and-trust.md) for revocation/leases,
  TPM/attestation, distributed authority, Secret and Accelerator design and
  unresolved questions;
- [foreign workloads](plans/foreign-workloads.md) for personality and
  guest design requirements and unresolved questions.

The archive retains original probe measurements and promotion history. Later
D3 clock/entropy and seeded-fixture clarifications in directions 31/33 were
preserved in their current owners, not attributed to the older snapshot.
Direction 2's later per-operation conservation and closure qualification also
remain in the authority plan. The [capacity plan](plans/memory-capacity.md) owns
memory requirements and residual sizing questions; direction 34 retains only
thread/SMP exploration, with its old memory measurements at the immutable origin.
I/O and Raspberry Pi construction investigations route to their archived
originals; current authority and target limits remain in architecture owners.
Composition notes retain current grants and verification boundaries; their
numbering, failed migrations and closure stories route to archived originals.
Historical removal is checked against the corresponding archive content, with
prior link migrations distinguished from changed facts. The requirements the roadmap
files retained now live in [plans](plans/README.md). They are not private history.

The `roadmap/` directory was retired after that migration. Sections for
milestones with a live gate were removed without a new archive snapshot. Their
last text is in this repository at commit `19866cefb1db78a0b113ee4852c011b6cb4c693e`,
under `roadmap/`.

Two files outside the process class still name a retired roadmap path:
`contracts/generation-manifest/v1/compositions/sel4.md` and
`components/build-support/src/lib.rs`. Each changes only under a work item that
owns it. The paths they name, `roadmap/07-architecture-portability.md` and
`roadmap/10-component-platform.md`, resolve at the product archive anchor above.

Local Notion exports under an ignored, untracked `spec/` directory are not part
of this product checkout or the immutable archive snapshot. They are not current
contract owners or required build inputs. Preserve local originals independently;
an archive reference here does not establish that those files were backed up.

The exact Duo transcript remains a product checker fixture at
[`evidence/duo/maee-smoke.log`](../evidence/duo/maee-smoke.log), SHA-256
`fc9802dbf74941d000f39429928ccddf06b6a2cf8188438415216741bfd3e801`.
The Framework observation remains in [`evidence/framework-cpu-boot/`](../evidence/framework-cpu-boot/)
with unchanged bytes, digest, tested-image binding and refusal semantics. This
migration makes no new QEMU or physical-machine claim. The Framework observation
remains about a superseded image until a new operator boot is observed.

The archive includes the 14 reachable product commits and a separate read-only
legacy GitHub snapshot with two commits. Older referenced commits remain
unresolved in those histories; no mapping was fabricated. Gitlinks are preserved,
but submodule object databases, hosted artifacts and external attachments are not
included. One existing archival link, the IO TCP plan's `folder/index.md`, remains
broken and is recorded in the archive inventory. A snapshot does not establish
that every historical environment is reconstructible.

## Current checks and rollback

`just docs_check` checks current local links/fragments, canonical UUID references,
and current commands. Historical prose is not validated against today's recipes;
its original checker stays at the archive revision. `just spec_tasks_check`
checks the work items and the backlog-first rule (V7). Neither requires history
checkout or network access.

The archive's `verify-archive.py` compares every candidate original with its Git
blob and rejects missing/mismatched bytes; it never deletes files. Local complete
bundles and an independent remote restoration were verified before cutover.
Same-machine backups are not an off-site guarantee, and remote protection was
not inspected or modified. Roll back product removal and consumers together by
reverting the cutover commit, without force-push or rewriting either history.

New exceptional investigations belong in the history repository. Record tested
revision and image digest, target/config, command, observations and limits,
artifact locator/digest, and retention. Ordinary changes require no investigation
or transcript; update owning product docs and canonical work-item evidence.
