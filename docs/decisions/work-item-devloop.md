# Work-item devloop v1.5

**Status:** Accepted
**Related work item:** `devloop-v1.5-bootstrap`, UUID
`01a1c46a-3c32-7055-aea0-ad0435d4c181`, closed (the last V1 item; its row is in
[`specs/legacy.zt`](../../specs/legacy.zt))
**Supersedes:** [`mandatory-spec-driven-work-items.md`](mandatory-spec-driven-work-items.md)
and [`spec-driven-work-item-bodies.md`](spec-driven-work-item-bodies.md)
**Amended by:** [`independent-review.md`](independent-review.md), which widens
who may give the V4 approval and adds V11

## Decision

v1.5 keeps the four V1 stages: planning, implementation, evidence and
closeout. It keeps the V1 pull-request classes. It changes only the six cost
sources V1 measured, listed below. Only one ratchet ships, R4. R1, R2, R3 and
the `Devloop-Role` trailer are not built. A grader change needs an approval
from `HUMAN_OWNERS` (V4).

Several pull requests per feature are deliberate. The planning pull request
merges first, so the spec and the exam reach `main` before the implementation.

## Premises

- People may lead development, or agents may. Every rule must hold in both
  modes. A rule that holds in one mode only states when it degrades and what
  replaces it.
- After the move to a private GitLab, another team continues development.
  That team has none of the earlier sessions' context. The rules must be
  readable from this record and the validator alone.
- Speed is not the first goal. Three pull requests per feature are
  acceptable. Re-records, bookkeeping commits and fields nobody reads are not.
- The validator uses no GitHub-only API. Every host dependency is one of the
  five functions in `scripts/spec/forge.py`.

## What V1 cost, and what v1.5 does

| V1 cost | Measured | v1.5 |
| --- | --- | --- |
| `repo/tasks` bookkeeping in the last 200 commits | 123 | Evidence goes to the `evidence` branch, not to a pull request. Closeout is one pull request per feature. |
| Evidence re-records per feature | about 5 | A record is keyed by its target's closure digest. There is no 24-hour TTL. |
| Paths evidence binds | 312 `codePaths` | Each target binds its own grader set. |
| Item body median | 8 KB, about 70% encoding | `task/v2` Zutai items built from helpers. |
| Behavior specs hidden in closed items | structural | `tasks_spec` derives the current promises from area files and terminal items (M4). |
| Fixing one grader | a new work item | A planning pull request edits an open item's exam directly. |

## Rules

`scripts/spec/check --base <sha>` is the only judge. Its inputs are the base
commit, the head checkout, the evidence commit, the pull request's author and
the approvals on the current head. Equal inputs give an equal verdict. The
judge's code comes from the base commit, so a pull request cannot change the
judge that judges it.

| Rule | Refuses |
| --- | --- |
| V1 class | A pull request with more than one class, or a path the class table does not list. |
| V2 planning first | An implementation path that no `owns` covers of an item that is on base and `#active` on head. |
| V3 no self-grading | An implementation pull request that touches the grader set of any bound target. |
| V4 grader approval | A grader-set change, an area invariant change, an existing contract schema change, or a change to `scripts/spec/`, `HUMAN_OWNERS`, `AGENT_ACCOUNTS`, `REVIEW_AGENTS` or `specs/allowed_signers`, without one approval on the head from `HUMAN_OWNERS` or `REVIEW_AGENTS` by someone other than the author. Any pull request while `HUMAN_OWNERS` lists fewer than two people. |
| V5 legal intent | An `intent` change outside `EDGES`. Entering `#deferred` or `#cancelled` without a V4 approval. |
| V6 closeout | A move to `terminal/` without a signed done witness, unless the item is `#cancelled`. Any later change to a terminal item. |
| V7 backlog first | A milestone, or an item under one, entering `#active` while a backlog bug is `#planned` or `#active`, or while a promise fails. |
| V8 R4 floor | A bound target whose floor on `negativeControlsRefused` drops, or loses its predicate, unless the same pull request adds an R4 known limit for that target. Adding a known limit needs a V4 approval. |
| V9 provenance | A `#human` quote shorter than 8 characters or a blanket answer, or a source that is a pull request number. Warning until three real features close. |
| V10 frozen promises | An added, changed or removed area requirement. An item's `supersedes` replaces one instead. |
| V11 independent review | Any pull request but a closeout whose head has no approval from `HUMAN_OWNERS` or `REVIEW_AGENTS` by someone other than the author. |

A **bound target** is one that an item in `.tasks/items/` that is not
cancelled, a terminal item nobody superseded, or an area requirement binds.
A target **bound by a promise** is one of the last two kinds only. A
planning pull request edits the exam of an open item directly. An exam bound
by a promise changes only with a new item. Both need a V4 approval.

`#planned` items are never recorded. The evidence workflow claims a target
only once its item is `#active`, so `main` never carries an expected failure.
A failing promise counts as an open backlog bug for V7. It blocks milestones,
not unrelated pull requests.

## Who is who

`HUMAN_OWNERS` lists the people who may approve: `iceice666`, `LmanTW` and
`CG-AA`. At the GitLab move, it lists at least two people of the team that
continues. `AGENT_ACCOUNTS` lists the agent accounts. The validator tells a
person from an agent by the pull request's author account, never by a
trailer. `REVIEW_AGENTS` lists the accounts whose approval is the review
agent's verdict. Today it lists `github-actions[bot]`, the account the
`Agent review` workflow submits its review with.

On GitHub, agents have no account of their own, and `AGENT_ACCOUNTS` is empty.
The person whose account an agent session pushes with is the author, and
cannot approve that pull request. This is a known limit until M6.

## Cutover

Cutover landed under the V1 item `devloop-v1.5-bootstrap`. It moved the V1
store into `specs/legacy.zt` and removed the `myque` and `devloop` pins,
`.devloop/`, the MyQue closeout and retirement workflows, `check-pr-scope.py`,
`check-work-items.py`, the work-item-lifecycle skill and the V1 `just`
recipes. `scripts/spec/check` became the only judge, and it blocks.

## Consequences

- `scripts/spec/check` is a required check, and no V1 tool remains. The
  [Cutover](#cutover) section names what cutover removed.
- The closeout bot needs its own token. On GitHub, each run mints one from a
  GitHub App: repository variable `CLOSEOUT_APP_ID`, secret
  `CLOSEOUT_APP_PRIVATE_KEY`. After the move, a GitLab project access token
  replaces it. A pull request opened with the workflow's built-in token
  triggers no checks, so V6 would never run.
- The evidence signing key stays in the `evidence` environment, which only
  `main` pushes reach. A key rotation adds a line to `specs/allowed_signers`
  and keeps the old one, so old records still verify.
- A pull request can edit the workflow that runs the judge, or add one that
  reports a passing check of the same name. A personal-account GitHub
  repository cannot require a workflow from `main`; only an organization
  ruleset can. The `main` ruleset requires the `Devloop v1.5 judge` and `CI`
  status checks and allows no bypass of the judge check. It required Code
  Owner review until 2026-11-17. [`independent-review.md`](independent-review.md)
  replaced that with a blocking finding of the review, which is a rule and
  not a mechanism. On GitLab, a protected pipeline definition replaces it.

## Revisit when

Process changes only when one of these holds, or after three real features:

1. Fewer than 2 of the last 10 grader approvals asked for a change. V4 has
   become a stamp: V8 becomes the main defence.
2. Accounts in `AGENT_ACCOUNTS` open more than 70% of implementation pull
   requests, measured from M6. Switch to agent-led mode and re-evaluate R2.
3. A terminal item and `tasks_spec` disagree on one behavior. `supersedes`
   is not enough; re-evaluate the area freeze.
4. One feature costs more than one bookkeeping commit. Inspect the closeout
   bot or the evidence workflow.

## Alternatives not taken

- Record a failing run right after planning merges, to show the exam
  discriminates. Each planning merge would cost a QEMU run, and most new
  targets fail at build time, so the signal is weak.
- A typed observation from the approver. The count of requested changes
  measures the same thing without a ritual for the next team.
- Measuring control strength. That is R2's scope.
