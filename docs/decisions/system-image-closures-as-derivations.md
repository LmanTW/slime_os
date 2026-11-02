# System-image closures commit sources, not in-tree digests

**Status:** Proposed
**Related work items:** `01a18732-ad06-744a-85e5-d50c903828f9` (step 1), `01a18cca-71e6-74e8-9161-ab2736a67bc1` (step 2), `01a19619-7518-7e31-b7d0-e7c8a9edcce3` (step 3)

## Context

A system-image closure records a SHA-256 identity for every input of an image build. Most inputs are
trees of this repository, such as `components/lib` and `just/`. Test-run records and negative build
cases copy a closure's identity. A change to any input tree therefore rewrites 174 derived files, and
two open pull requests that touch input trees always conflict on them (issue #848). On 2026-10-29, 15
of the latest 40 merged pull requests changed system-image closure paths.

The in-tree digests repeat what the commit already fixes. They do not add reproducibility. Today the
same-commit reproducibility is proven by building every closure twice in PR CI and comparing every
output. Nothing records whether a later rebuild of a commit gives the same bytes.

## Decision

1. Commit pins only for inputs outside the repository: `sel4/pins.toml`, the submodule gitlinks,
   `flake.lock` and the toolchain.
2. A committed closure becomes a source of composition choices and input locators. Each consumer
   computes the resolved closure from its checkout, with today's SHA-256 tree digest over the files git
   lists.
3. A build over a dirty input tree may run. It is marked dirty and is never evidence.
4. Test-run records and negative build cases name their closure, not its identity.
5. Reproducibility across commits is recorded after merge by a nightly workflow, as attestations in
   the git notes ref `refs/notes/image-attestations`. No pull request diff carries one. The host class is
   the default devShell derivation and `uname -m`.

[`plans/system-image-closure-derivations.md`](../plans/system-image-closure-derivations.md) holds the
model, the steps and the measurements.

## Alternatives and trade-offs

- **Keep committed digests and automate regeneration.** A local command or a bot rebases a pull
  request and regenerates its derived commit. This keeps today's guarantees and removes the manual
  step. It keeps the conflicts and the CI cost of `--check`, and a bot needs push access to fork
  branches.
- **Identities from git object ids (`git rev-parse HEAD:<path>`).** This is simpler, but this
  repository's object format is SHA-1. It also cannot describe a dirty tree, so every local QEMU
  iteration would need a commit first.
- **Attestations committed in the tree, or on an orphan branch.** In the tree, attestations change
  whenever image bytes change, so concurrent product pull requests would conflict on them instead. An
  orphan branch is visible in GitHub's interface, but it adds a branch that history tools must
  ignore. Git notes were chosen.
- **Drop only the recipes from the inputs (PR #851).** This fixes recipe-only changes. It leaves every
  product change rewriting the corpus.

## Consequences

- A change to an input tree rewrites no derived file once steps 1 and 2 land.
- CI drops the corpus freshness check from the pull request path. Each plane gate resolves only its
  own closure.
- A contributor can test uncommitted changes in QEMU without regenerating anything. The build result
  says it was dirty.
- Attestations need a workflow with write access to `refs/notes/*`, and a clone fetches them only when
  asked to.

## Revisit conditions

- A build is shown to read a file that `git ls-files` does not list.
- The repository moves to the SHA-256 object format, which would make git tree ids an option.
- A hermetic builder makes attestations comparable across host classes.
