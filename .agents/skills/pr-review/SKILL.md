---
name: pr-review
description: Rules that bound any review of a Slime OS pull request and any answer to one — what counts as a finding, how severity is assigned, one review per head, consistency across rounds, and how an author reproduces, fixes, or declines a finding. Use when asked to review a PR, to triage or answer review threads (including review-bot findings), or to decide whether a PR is ready. For the adversarial procedure against a task/v2 work item, use `spec-review` alongside this.
---

# PR review

These rules bind every reviewer of a PR — a person, a review bot, or an
agent asked to review — and the author answering the review.
`AGENTS.md` carries the summary that review bots read; this skill is the full
text. `.agents/skills/spec-review/SKILL.md` is the procedure for an
implementation PR against its task/v2 work item; the rules here bound what any
review posts.

A review's job is to find where the diff, the checker it binds, and the
landed work item disagree, and to say so with a file and line.

## The item bounds the review

Read the work item (`.tasks/items/<slug>.zt`: requirements, acceptances,
`owns`, `nonGoals`), the PR description, and the existing review threads before
reading the diff.

A process PR — `.github/`, `CONTRIBUTING.md`, `AGENTS.md`, `.agents/`,
`docs/`, and the other process paths in the `scripts/spec/check` class
table — has no item. There the bound is the rules
in `AGENTS.md` the PR claims to follow and the claims its description makes:
a finding names the rule or claim the diff contradicts, with the file and
line, and the input or reader that would be misled. The absence of an
item neither makes such a PR unreviewable nor excuses a defect in it.

- A finding names what the diff breaks — a requirement or acceptance of the
  landed item, an invariant the code or its contract states, or a
  repository rule in `AGENTS.md` — with the file and line and the input
  that produces the wrong result. An item-specific acceptance (an exact
  refusal case, a pinned count) grounds a finding on its own; no
  repository-wide rule needs to be broken as well.
- An exam's case count and control floor belong to the planning item: "this
  boundary could also be exercised" is not a finding unless a requirement
  statement claims that boundary, because every added case is a planning
  change to the item.
- A missing scenario the reviewer believes matters goes in one comment that
  proposes a follow-up item, not in one comment per case.
- A limit the PR description declares under known limits or invariants is a
  decision to weigh, not a gap to report; a reviewer who thinks the decision
  is wrong says why, once, on the thread for it.

## Severity states a consequence

A finding is **blocking** only when:

- a gate can pass while its claim is false;
- a refused input is accepted;
- an authority, lifetime, or determinism rule is broken;
- a format crossing a boundary has no Zutai contract;
- the recipe cannot pass as landed;
- the PR adds a workflow or a job whose check name equals a required check,
  or that submits a review, because either could report the PR's own verdict.

A real defect in the diff whose fix is local is a **non-blocking** finding.

Everything else — style, an alternative design, hardening the item does not
require — is a **suggestion**, labelled as one; it never blocks a merge and
is not raised again on a later head.

A finding that would require the PR to carry what
`scripts/spec/check` refuses (another class, a path outside `owns`, a
bound grader file), or what the landed item excludes,
is addressed to the planning process in one comment, not to the PR.

## One review per head, bounded in size

Review the whole diff once at the head the review is for. A review of a
later head covers the pushed delta and the threads that delta answers; it
does not re-open the rest of the diff to look for new cases.

Post the findings that change the verdict. If a review would post more than
ten, the diff has a structural problem: name it, give the strongest findings,
and stop. Do not post the same finding twice in one round under two titles,
and do not reproduce a finding another tool already posted.

## Consistency across rounds

Before posting, read every open and resolved thread.

- A finding that restates an open thread is a reply on that thread.
- A finding that contradicts an earlier finding, or asks to undo a change an
  earlier round asked for, says so, names the earlier thread, and states
  what evidence changed; a reviewer who cannot name that evidence withholds
  the finding.
- A thread the author has answered with a question or a declared decision
  waits for the human who owns the PR; re-posting it on the next head is not
  an answer.

## Answering a review

- **Reproduce before fixing.** A finding that does not reproduce is answered
  with what was tried and stays open for the reviewer. The reply to a fixed
  finding says what reproduced, the commit that fixed it, and what control
  now refuses the case.
- **Declining is legitimate.** When a finding is outside the item's scope,
  contradicts the landed spec, or asks for what the PR cannot carry, reply
  with the reason and leave the thread for the human.
- **Triage before fixing.** The author's reply to a round opens with one
  line per finding: the input that breaks it, whether it changes product
  behavior or only tooling, documentation or process, and the size of the
  fix. Fixes follow in the same push.
- **One push per round.** Answer every thread of a round in one push rather
  than one push per finding, since each push starts another round.
- **Revise the item once.** Do not revise the item to satisfy a suggestion;
  collect scope changes into one planning PR, or open a follow-up item. A
  blocking finding against an exam whose pinned count must move does need
  a planning PR that revises the item; say so in the reply.
- **Know when you are done.** When a round yields nothing blocking, the PR is
  ready and the author does not request another round.
- **Threads hold the history.** The PR description describes the head as it
  is and does not accumulate a per-round changelog.
- An agent's or bot's review is review, not verification evidence; do not
  list "independent review: no blockers" in the PR's verification table.

## When the author stops and asks

The author fixes nothing in a round and asks the human in one PR comment,
linking [`HUMAN.md`](../../../HUMAN.md), when either holds:

- A third consecutive round raises a new finding on the same subject. The
  comment names the subject, the design choice that keeps producing
  findings, and the decision that would close the whole class (for example:
  require storage to equal the declared configuration instead of bounding it
  from below).
- A non-blocking finding lands on process or verification text or code:
  `scripts/`, `.tasks/`, `specs/`, `.agents/`, `AGENTS.md`, or
  `docs/` outside `docs/architecture/`. These are collected into one
  follow-up comment for the human to accept or drop, not fixed in the PR.

The comment offers two or three options with their cost and a
recommendation, so the human can answer `Decision: <option>. Because
<reason>.` That answer is a declared decision under consistency across
rounds; a finding that follows from it is not re-raised.
