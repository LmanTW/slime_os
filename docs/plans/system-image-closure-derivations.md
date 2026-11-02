# System-image closures as derivations

Steps 1, 2 and 3 of this plan are implemented. It moves the system-image closure corpus from committed input digests to
committed sources, so a change to an input tree stops rewriting derived records. The decision and
its alternatives are in
[`decisions/system-image-closures-as-derivations.md`](../decisions/system-image-closures-as-derivations.md).
Step 1, work item `01a18732-ad06-744a-85e5-d50c903828f9`, is implemented. Step 2, work item
`01a18cca-71e6-74e8-9161-ab2736a67bc1`, is implemented. Step 3, work item `01a19619-7518-7e31-b7d0-e7c8a9edcce3`, is implemented.

## Problem

Before step 2, a closure under `contracts/system-image-closure/v2/closures/` recorded a SHA-256 identity for every
input tree, including the repository's own trees such as `components/lib`. Each test-run record and
each negative build case copies a closure identity. A change to any input tree therefore rewrites
174 files: 103 closures, 6 negative build cases and 65 test-run records. Two open pull requests that
touch an input tree conflict on those files, whatever their content. On 2026-10-29, 15 of the latest
40 merged pull requests changed system-image closure paths.

The committed digests of in-tree inputs add no pin. The commit already fixes those bytes. Only inputs
outside the repository need a recorded pin: `sel4/pins.toml`, the submodule gitlinks, `flake.lock`
and the toolchain.

## Target model

| Layer | Content | Location | Changes when |
| --- | --- | --- | --- |
| Closure source | composition, implementations, roles, build parameters, input locators | `contracts/system-image-closure/v3/closures/`, committed | a composition changes |
| Resolved closure | the source, one SHA-256 identity per input, and the derivation id | computed from the checkout, never committed | an input changes |
| Attestation | commit, derivation id, host class, output digests | the git notes ref `refs/notes/image-attestations` on the origin | image bytes change |

The rules:

- **In-tree identity.** An input's identity keeps today's `tree_digest` encoding over SHA-256. The file
  set is what `git ls-files --cached --others --exclude-standard` lists, so an ignored file is not part
  of the identity.
- **Dirty builds.** A build is dirty if a tracked file under an input is modified, or an untracked or
  ignored file sits under an input. A dirty build may run any gate locally. Its build result records
  `dirty=true`, and no attestation or devloop evidence may name it.
- **Derivation id.** On a clean tree the derivation id equals today's `closureIdentity`. Build caches,
  the build result and the SDK release record keep their meaning.
- **Test runs and negative cases.** A test-run record names its closure. A negative build case names
  its base closure.
- **SDK.** The published SDK carries a fully resolved closure, rendered from the release commit.
- **Attestations.** A workflow runs nightly and on demand at the head of `main`. It builds each attested
  closure into a fresh directory and writes one note on that commit under `refs/notes/image-attestations`,
  in the `contracts/image-attestation/v1` format. For one host class, an equal derivation id must give
  equal output digests. The writer refuses, and writes nothing, when an earlier note breaks that. The
  first version attests six closures, the closure-derivation exam's sample. PR CI does not read
  attestations. It keeps the check that two builds of one closure agree.
- **Concurrent writers.** Runs of the workflow queue in one concurrency group and never cancel a running
  run. The writer fetches the notes before it compares, never replaces a note, and after a rejected push
  fetches, compares again and retries.
- **Host class.** The host class is the Nix store path of the default devShell derivation and `uname -m`.
  The runner image is recorded but is not part of the class.
- **A refused run.** A run that finds a mismatch fails and writes no note. A maintainer files the
  defect.

## Steps

| Step | Change | Derived files no longer rewritten per input change | Gate |
| --- | --- | --- | --- |
| 1 | Test-run records and negative build cases name their closure (`contracts/system-test-run/v2`) | 65 + 6 | `just system_test_run_reference_check` |
| 2 | Closure v3 holds locators only. The resolver is the closure generator, called in memory over the git-visible file set, with the dirty rule. | 103 | `just closure_derivation_check` |
| 3 | Attestation contract, the notes writer, its nightly workflow and its check | none; adds evidence across commits | `just image_attestation_check` |

Step 1 precedes step 2, because the runs must stop copying identities before the closures stop
recording them. Step 2 precedes step 3, because an attestation names a derivation id. The nightly run
is the rebuilder: each run rebuilds closures whose derivation ids earlier notes already attest.

## Interfaces step 2 is judged through

`scripts/check/check-closure-derivations.py` calls these as commands:

| Command | Contract |
| --- | --- |
| `python3 scripts/generate/generate-system-image-closures.py` | write the sources under `contracts/system-image-closure/v3/closures/` |
| `… --check` | refuse a stale source |
| `… --resolve NAME --output PATH --report REPORT` | write the resolved v2 closure to `PATH`, and a `contracts/closure-resolution/v1` report with `name`, `derivationId` and `dirty` to `REPORT` |
| `python3 scripts/build/build-system-image.py contracts/system-image-closure/v3/closures/NAME.zti OUT` | build, and write `OUT/build-result.zti`, a version 2 `SystemImageBuildResult` with `closureIdentity` and `dirty` that `decodeSystemImageBuildResult` accepts |

The exam reads both records only through their Zutai decoders.

## Measured feasibility of step 2

These measurements were taken at `ffb4dc67` on one darwin host, with a read-only spike that is not part
of the repository:

- The git-visible digest equals today's walk digest, and the committed identity, for all 124 tree
  inputs the closures name.
- Over `components/lib`, the two digests agree on a modified file, an untracked file, a deleted file and
  an added executable bit. They differ only when an ignored file is present: the walk includes it and
  the git-visible digest leaves it out. The dirty rule covers that case.
- Rendering one closure in memory with the existing generator takes 0.02–0.3 s with a warm Zutai
  cache, and 6.4 s for a closure over a computed system. With the cache disabled it takes 9.9 s and
  16.5 s. Every rendered closure equaled the committed file byte for byte.

## Measured feasibility of step 3

These measurements were taken at `6e1e22c9` on one darwin host:

- In a scratch clone, `sel4-channel` builds in 67 s cold and 51 s warm. The two builds' five output
  digests are equal.
- `nix eval --raw .#devShells.aarch64-darwin.default.drvPath` takes 3–5 s and prints the same path in
  two checkouts of one commit.
- A bare remote's `pre-receive` hook can add a note and reject the push, which is how the exam plays a
  concurrent writer.

## Invariants

- The build key is a pure function of declared inputs.
- A clean build is reproducible within one host class.
- A dirty build never becomes evidence.
- A scenario's build parameters and profiles stay part of the closure source and the derivation id.
- A negative build case is never a system-image closure.
- An SDK consumer builds without this repository's history.
- The attestation crosses a persistence boundary, so it has a Zutai contract.
- A closure proves bytes. A test run proves behavior. An attestation proves bytes across commits
  within one host class, and nothing about a boot.

## Known limits

- Git notes are not shown in GitHub's web interface. A clone fetches them only when asked to.
- A clone without submodules cannot resolve a submodule input.
- Cross-host comparison waits for a hermetic builder.
