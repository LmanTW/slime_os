# Every pull request needs one independent review, by a person or by the review agent

**Status:** Accepted
**Decided by:** the project's human owner, 2026-11-17
**Amends:** rule V4 and the section "Who is who" of
[`work-item-devloop.md`](work-item-devloop.md), and adds a review rule for
every pull request

## Context

Before this decision, V4 required one approval on the head from a person in
`HUMAN_OWNERS` other than the author. The `main` ruleset also required Code
Owner review for `.github/`, `scripts/spec/` and the owner lists.

Agents have no account on GitHub. An agent session pushes with a person's
account, so that person is the author and cannot approve. `HUMAN_OWNERS` lists
three people, and one of them opens most pull requests.

On 2026-11-17 two merges showed what happens in practice:

- Pull request 1009 changed `.github/workflows/spec-judge.yml`. It had no
  review when its author merged it.
- Pull request 1008 started a milestone. Its author merged it while the
  `Devloop v1.5 judge` check was a failure, because the judge had exited
  before a verdict.

The human approval replaced an agent review loop, so that a person would read
each merge. The owner reports that this did not happen: the owner merges the
owner's own pull requests directly, and merges another person's pull request
once the review agent reports nothing blocking.

[`work-item-devloop.md`](work-item-devloop.md) names this case in its first
revisit condition: V4 has become a stamp.
`python3 scripts/spec/forge.py review-changes --forge github` prints the
metric that condition uses.

A rule that the owner bypasses each time has two costs. The record claims a
control that does not run. And a required check that is red for a known reason
teaches the owner to merge over red, which hides a red that has a real cause.

## Decision

1. Every pull request needs one independent review of its current head. Two
   things satisfy it:
   - an approving review from a person in `HUMAN_OWNERS` other than the
     author, or
   - a verdict of the review agent that reports no blocking finding.
2. A closeout pull request is the one exception. It moves an item file
   unchanged, and V6 judges it from a signed witness.
3. The same review satisfies V4. The paths V4 names, the judge's own paths
   among them, have no stricter rule.
4. The rule is the same for every author. A pull request of an owner needs the
   review as any other does.
5. The review agent runs from the workflow on `main`, under its own account. A
   pull request cannot change the workflow or the skill that reviews it.
6. A verdict binds to one head commit. A push needs a new review.
7. The review workflow records its verdict as a review on the head commit:
   an approval when no finding is blocking, a request for changes otherwise.
   A step of the workflow derives it from the agent's structured result. The
   judge reads it through the `approvers` function it already has, and a new
   list, `REVIEW_AGENTS`, names the accounts whose approval counts.
8. Nobody merges over a red judge. The `main` ruleset allows no bypass of the
   `Devloop v1.5 judge` check. If the judge exits without a verdict, a process
   pull request repairs the judge first.
9. The author never reviews the author's own pull request. A session that
   opened a pull request does not produce its verdict.
10. The review agent reports as blocking a pull request that adds a workflow
    or a job whose check name equals a required check, or that submits a
    review.
11. No rule relies on a person reading a diff. A person decides what an agent
    asks: the cases [`AGENTS.md`](../../AGENTS.md) and
    [`HUMAN.md`](../../HUMAN.md) hand to a person, and the agent defaults a
    pull request lists under `Decisions`.
12. The review rules in [`AGENTS.md`](../../AGENTS.md) stay as they are. One
    review per head, and the author asks a person when a third round raises a
    new finding on the same subject.

## Implementation state

The judge enforces decisions 1 to 7 and 9 as rules V4 and V11. The `main`
ruleset carries decision 8. Only an owner can change the ruleset, and no file
in the repository states it, so the last row below records the owner's report.

| Part | Where it lives | State |
|---|---|---|
| The verdict as a review on the head commit | `.github/workflows/agent-review.yml` | landed |
| The accounts whose approval counts | `REVIEW_AGENTS` | landed |
| V11, and V4 accepting the same review | `scripts/spec/check`, `scripts/spec/rules.py`, `scripts/spec/e2e` | landed |
| The judge runs again after a verdict | `.github/workflows/agent-review.yml` | landed |
| The blocking finding of decision 10 | `.agents/skills/pr-review/SKILL.md` | landed |
| The rule text | `work-item-devloop.md`, `AGENTS.md`, `CONTRIBUTING.md` | landed |
| GitHub Actions may approve a pull request | the repository's Actions settings | the owner enabled it on 2026-11-17 |
| No Code Owner review, and no bypass of the judge check | the `main` ruleset | the owner reported it changed on 2026-11-17 |
| `.github/CODEOWNERS` | removed | landed |

## Alternatives

- **Keep V4 and bypass it.** Nothing changes in the code. The record keeps a
  claim that does not hold, and merging over red stays normal.
- **Remove V4.** An implementation could then change its own exam with no
  second reader of any kind.
- **Require the review for grader changes only.** An implementation pull
  request would then merge with no reader, because the owner does not read
  diffs.
- **Give agents their own accounts and list them in `AGENT_ACCOUNTS`.** This
  is the plan for the GitLab move. It separates the author from the approver,
  and it does not add a second person.
- **Keep a human approval for the judge's own paths only.** Those paths can
  disable every check, and they change rarely. The owner chose one rule for
  every path, because a stricter rule would be bypassed as V4 is today.

## Consequences

- No person reads a change by default. The second reader may be an agent of
  the same model family as the author, and their blind spots correlate.
- Each head of each pull request costs one agent review. The review rules
  bound the rounds, not the count of heads.
- Text in a pull request can address the review agent. Running the reviewer
  from `main` limits this and does not remove it.
- GitHub matches a required check by name. Without Code Owner review, a pull
  request can add a workflow that reports a passing check of a required name,
  or that approves the pull request under the review account. Decision 10 is
  the only guard, and it is an agent's finding, not a mechanism.
- V8, the floor on `negativeControlsRefused`, becomes the main mechanical
  defence. The judge enforces it for the predicates that items and areas
  state. It does not compare the counts of records.
- With no bypass, a judge that exits without a verdict blocks every pull
  request that reaches that path until a process pull request repairs it.
- The pull request that changes V4 is judged by the V4 it replaces. It needs
  an approval from another owner once more.

## Revisit when

- A person finds a blocking defect in a change that the review agent passed.
  Count these.
- A second person reviews regularly, or the GitLab move gives agents their own
  accounts.
- The code host cannot record the verdict as a review under an account that
  `REVIEW_AGENTS` can name.
- A pull request reports a required check name from a workflow it added.
