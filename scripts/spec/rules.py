"""The v1.5 validator rules, shared by `scripts/spec/tasks` and `scripts/spec/check`.

Every rule is a pure function of what it is given: items and areas at base
and head, the recipes at base and head, the evidence commit, the pull
request's author and its approvers. Rule ids follow
`docs/decisions/work-item-devloop.md`: V1 class, V2 planning first, V3 no
self-grading, V4 grader approval, V5 legal intent, V6 closeout, V7 backlog
first, V8 R4 floor, V9 provenance, V10 frozen promises; and from
`docs/decisions/independent-review.md`, V11 independent review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import lib

# Accounts whose approval is the review agent's verdict. Read from the judge's
# own commit, like HUMAN_OWNERS; `scripts/spec/check` extracts it beside
# `lib.JUDGE_PATHS`.
REVIEW_AGENTS = "REVIEW_AGENTS"

MILESTONE_LISTS = ("owns", "nonGoals", "requirements", "acceptance", "invariants", "decisions")
# V9: a `#human` quote must be a concrete decision or example.
QUOTE_MIN = 8
BLANKET = re.compile(r"照\s*default|都同意|你選|你决定|你決定|全部照|as default|all defaults?|you (choose|decide)|^\s*(ok|yes|lgtm|好|可以|同意)\s*[.!。]?\s*$", re.I)
# A source a code-host move would break: a bare PR or issue number or URL.
FRAGILE_SOURCE = re.compile(r"^\s*(#?\d+|(pr|issue|mr)\s*#?\d+|https?://\S+/(pull|issues|merge_requests)/\d+\S*)\s*$", re.I)
# V9 blocks once this many real features have closed.
V9_BLOCKS_AFTER = 3


@dataclass
class Findings:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    approvals: list[str] = field(default_factory=list)  # V4/V5 reasons that need an approval

    def error(self, rule: str, message: str) -> None:
        self.errors.append(f"{rule}: {message}")

    def warn(self, rule: str, message: str) -> None:
        self.warnings.append(f"{rule}: {message}")

    def needs_approval(self, rule: str, message: str) -> None:
        self.approvals.append(f"{rule}: {message}")


# --- Structure ---------------------------------------------------------------


def check_sources(root: Path, findings: Findings) -> None:
    """`.tasks/{items,terminal}/{schema,helpers}.zt` are byte-identical copies of contracts/task/v2."""
    for stray in (root / ".tasks").rglob("*.zti") if (root / ".tasks").is_dir() else []:
        findings.error("format", f"{stray.relative_to(root)}: .zti is computed, never committed")
    if not lib.item_files(root):
        return
    for directory in ("items", "terminal"):
        for name in lib.ITEM_SOURCES:
            copy = root / ".tasks" / directory / name
            canonical = lib.TASK_CONTRACT / name
            if (root / ".tasks" / directory).is_dir() and (not copy.is_file() or copy.read_bytes() != canonical.read_bytes()):
                findings.error("format", f".tasks/{directory}/{name} must be a byte-identical copy of contracts/task/v2/{name}")


def check_provenance(where: str, provenance: object, findings: Findings) -> None:
    kind, body = lib.tag(provenance), lib.payload(provenance)
    if kind == "human" and not (body.get("quote", "").strip() and body.get("source", "").strip()):
        findings.error("format", f"{where}: a #human provenance needs a quote and a source")
    if kind == "acceptedDefault" and not body.get("source", "").strip():
        findings.error("format", f"{where}: an #acceptedDefault provenance needs a source")
    if kind == "decision" and not (lib.ROOT / body.get("page", "")).is_file():
        findings.error("format", f"{where}: provenance names {body.get('page')!r}, which does not exist")


def provenances(item: lib.Item) -> list[tuple[str, object]]:
    v = item.value
    rows = [(f"requirement {r['id']}", r["provenance"]) for r in v["requirements"]]
    rows += [(f"decision {d['id']}", d["provenance"]) for d in v["decisions"]]
    rows += [(f"invariant {i['id']}", i["provenance"]) for i in v["invariants"]]
    rows += [("nonGoal", n["provenance"]) for n in v["nonGoals"]]
    rows += [(f"known limit {k['subject']}", k["provenance"]) for k in v["knownLimits"]]
    return rows


def check_item(item: lib.Item, recipes: lib.Recipes, area_ids: set[str], findings: Findings) -> None:
    v, where = item.value, item.where
    if v["slug"] != item.path.stem or not lib.SLUG.match(v["slug"]):
        findings.error("format", f"{where}: slug {v['slug']!r} must be the file name and match {lib.SLUG.pattern}")
    if not lib.UUID7.match(v["id"]):
        findings.error("format", f"{where}: id {v['id']!r} is not a UUIDv7")
    if v["area"] not in area_ids:
        findings.error("format", f"{where}: area {v['area']!r} has no specs/<area>.zt")
    for name in ("title", "problem"):
        if not v[name].strip():
            findings.error("format", f"{where}: {name} is empty")
    if item.kind == "milestone":
        for name in MILESTONE_LISTS:
            if not v[name]:
                findings.error("format", f"{where}: a milestone needs a non-empty {name}")
    elif not v["owns"]:
        findings.error("format", f"{where}: owns is empty; V2 maps an implementation pull request to an item through it")
    ids = [a["id"] for a in v["acceptance"]]
    if len(ids) != len(set(ids)):
        findings.error("format", f"{where}: acceptance ids repeat: {ids}")
    if not [a for a in v["acceptance"] if a["mandatory"] and lib.tag(a["check"]) in {"observed", "clause"}]:
        findings.error("format", f"{where}: an item needs at least one mandatory h.observed or h.clause acceptance")
    for target in item.targets():
        if target not in recipes:
            findings.error("format", f"{where}: acceptance binds {target!r}, which `just --dump` does not declare")
    binders = set(ids)
    for requirement in v["requirements"]:
        binders.add(requirement["id"])
        if not requirement["statement"].strip():
            findings.error("format", f"{where}: requirement {requirement['id']} has an empty statement")
        for named in requirement["acceptance"]:
            if named not in ids:
                findings.error("format", f"{where}: requirement {requirement['id']} names acceptance {named!r}, which this item lacks")
    for decision in v["decisions"]:
        for bound in decision["binds"]:
            if bound not in binders:
                findings.error("format", f"{where}: decision {decision['id']} binds {bound!r}, which is no requirement or acceptance of this item")
    for limit in v["knownLimits"]:
        if limit["ratchet"] != "R4" or not limit["subject"].strip() or not limit["reason"].strip():
            findings.error("format", f"{where}: known limit {limit['subject']!r} needs ratchet R4, a subject and a reason")
    for label, provenance in provenances(item):
        check_provenance(f"{where} {label}", provenance, findings)


def check_area(area: lib.Area, recipes: lib.Recipes, findings: Findings) -> None:
    where = area.path.relative_to(lib.ROOT).as_posix() if area.path.is_relative_to(lib.ROOT) else str(area.path)
    if area.id != area.path.stem or not lib.SLUG.match(area.id):
        findings.error("format", f"{where}: area id {area.id!r} must equal the file name")
    for requirement in area.requirements:
        label = f"{where} requirement {requirement['id']}"
        if not lib.UUID7.match(requirement["id"]):
            findings.error("format", f"{label}: id is not a UUIDv7")
        for kind, body in lib.area_acceptances(requirement):
            if kind == "observed" and body["justTarget"] not in recipes:
                findings.error("format", f"{label}: binds {body['justTarget']!r}, which `just --dump` does not declare")


def check_store(items: list[lib.Item], areas: list[lib.Area], recipes: lib.Recipes, findings: Findings) -> None:
    """Every item and area alone, then the links between them."""
    area_ids = {a.id for a in areas}
    for area in areas:
        check_area(area, recipes, findings)
    requirement_ids = {r["id"] for a in areas for r in a.requirements}
    by_id: dict[str, lib.Item] = {}
    for item in items:
        check_item(item, recipes, area_ids, findings)
        if item.id in by_id:
            findings.error("format", f"{item.where}: id {item.id} is already used by {by_id[item.id].where}")
        by_id[item.id] = item
    for item in items:
        for named in [item.value["parent"]] * bool(item.value["parent"]) + item.value["depends"]:
            if named not in by_id:
                findings.error("format", f"{item.where}: parent or depends names {named!r}, which is no item")
        for entry in item.value["supersedes"]:
            owner, _, requirement = entry.partition("/")
            target = by_id.get(owner)
            if requirement:
                ok = target is not None and requirement in {r["id"] for r in target.value["requirements"]}
            else:
                ok = (target is not None and target.terminal) or entry in requirement_ids
            if not ok:
                findings.error("format", f"{item.where}: supersedes {entry!r}, which is no terminal item, item requirement or area requirement")
    gone = lib.superseded(items)
    for item in items:
        if item.terminal and item.id not in gone:
            for target in item.targets():
                if target not in recipes:
                    findings.error("V10", f"{item.where}: terminal item binds {target!r}, which no longer exists; supersede the item to retire it")


# --- Transitions -------------------------------------------------------------


def check_transitions(base: list[lib.Item], head: list[lib.Item], findings: Findings) -> None:
    """V5: every intent change is in EDGES; entering #deferred or #cancelled needs an approval."""
    before = {i.id: i for i in base}
    for item in head:
        old = before.get(item.id)
        if old is not None and old.terminal and item.terminal:
            continue
        previous = old.intent if old is not None else None
        if previous == item.intent:
            continue
        if item.intent not in lib.EDGES.get(previous, frozenset()):
            findings.error("V5", f"{item.where}: intent {previous or 'new'} -> {item.intent} is not in EDGES")
        elif item.intent in lib.APPROVED_INTENTS:
            findings.needs_approval("V5", f"{item.where} enters #{item.intent}")


def children(items: list[lib.Item], milestone: str) -> set[str]:
    found: set[str] = set()
    pending = [milestone]
    while pending:
        parent = pending.pop()
        for item in items:
            if item.value["parent"] == parent and item.id not in found:
                found.add(item.id)
                pending.append(item.id)
    return found


def check_backlog(base: list[lib.Item], head: list[lib.Item], failing_promises, findings: Findings) -> None:
    """V7: no milestone, or item under one, enters #active while a backlog bug is open or a promise fails.

    `failing_promises` is a callable returning the failing promises; it is
    only called when some milestone work actually starts."""
    before = {i.id: i.intent for i in base}
    milestones = {i.id for i in head if i.kind == "milestone" and not i.terminal}
    under = set(milestones)
    for milestone in milestones:
        under |= children(head, milestone)
    starting = [i for i in head if i.id in under and i.intent == "active" and before.get(i.id) != "active"]
    if not starting:
        return
    bugs = [i for i in head if i.kind == "bug" and not i.terminal and i.intent in {"planned", "active"}]
    failing = failing_promises()
    for item in starting:
        for bug in bugs:
            findings.error("V7", f"{item.where} enters #active while backlog bug {bug.where} is #{bug.intent}")
        for promise in failing:
            findings.error("V7", f"{item.where} enters #active while promise {promise} fails")


CONTROLS = "negativeControlsRefused"


def control_floor(predicates: list) -> int | None:
    """The lower bound the predicates put on `negativeControlsRefused`, or None."""
    floor = None
    for predicate in predicates:
        kind, body = lib.tag(predicate), lib.payload(predicate)
        if body.get("key") != CONTROLS:
            continue
        bound = body.get("equals") if kind == "count" else body.get("min") if kind == "atLeast" else None
        if bound is not None:
            floor = bound if floor is None else max(floor, bound)
    return floor


def control_floors(items: list[lib.Item], areas: list[lib.Area]) -> dict[str, int | None]:
    """Each bound target's floor on `negativeControlsRefused`: the highest
    lower bound among the mandatory acceptances that bind it, or None when
    none of them bounds the count. The items and areas are those
    `lib.bound_targets` counts. An advisory acceptance sets no floor, because
    `lib.item_done` never reads its predicates."""
    gone = lib.superseded(items)
    floors: dict[str, int | None] = {}

    def note(target: str, predicates: list) -> None:
        floor = control_floor(predicates)
        known = floors.get(target)
        floors[target] = floor if known is None else known if floor is None else max(known, floor)

    for item in items:
        if (item.terminal and item.id not in gone) or (not item.terminal and item.intent != "cancelled"):
            for acceptance in item.value["acceptance"]:
                if lib.tag(acceptance["check"]) == "observed":
                    body = lib.payload(acceptance["check"])
                    note(body["justTarget"], body["predicates"] if acceptance["mandatory"] else [])
    for area in areas:
        for requirement in area.requirements:
            if requirement["id"] not in gone:
                for kind, body in lib.area_acceptances(requirement):
                    if kind == "observed":
                        note(body["justTarget"], body["predicates"])
    return floors


def check_control_floor(base_items, base_areas, head_items, head_areas, findings: Findings) -> None:
    """V8 (R4): a bound target's floor on `negativeControlsRefused` never
    drops, unless this pull request adds an R4 known limit for that target.
    A known limit covers the pull request that adds it and no later one, and
    adding it needs an approval."""
    known = {(item.id, limit["subject"]) for item in base_items for limit in item.value["knownLimits"]}
    allowed: set[str] = set()
    for item in head_items:
        for limit in item.value["knownLimits"]:
            if limit["ratchet"] == "R4" and (item.id, limit["subject"]) not in known:
                allowed.add(limit["subject"])
                findings.needs_approval("V8", f"{item.where} adds an R4 known limit for {limit['subject']}")
    before, after = control_floors(base_items, base_areas), control_floors(head_items, head_areas)
    for target, floor in sorted(before.items()):
        if floor is None or target not in after or target in allowed:
            continue
        now = after[target]
        if now is None or now < floor:
            findings.error("V8", f"{target}: the floor on {CONTROLS} drops from {floor} to {'none' if now is None else now}; the item that lowers it must add an R4 known limit for {target}")


def check_provenance_quality(items: list[lib.Item], findings: Findings) -> None:
    """V9: warnings, which become errors once V9_BLOCKS_AFTER real features closed."""
    closed = sum(1 for i in items if i.terminal and i.kind != "milestone")
    report = findings.error if closed >= V9_BLOCKS_AFTER else findings.warn
    for item in items:
        if item.terminal:
            continue
        for label, provenance in provenances(item):
            if lib.tag(provenance) != "human":
                continue
            body = lib.payload(provenance)
            quote, source = body.get("quote", ""), body.get("source", "")
            if len(quote.strip()) < QUOTE_MIN or BLANKET.search(quote):
                report("V9", f"{item.where} {label}: quote {quote!r} is not a concrete decision or example; use h.acceptedDefault for a blanket answer")
            if FRAGILE_SOURCE.match(source):
                report("V9", f"{item.where} {label}: source {source!r} names a pull request or issue; record a commit sha or a repository path")


def check_frozen_areas(base: list[lib.Area], head: list[lib.Area], findings: Findings) -> None:
    """V10: area requirements are frozen; an item's `supersedes` replaces one.
    Invariant changes need an approval (V4)."""
    before = {r["id"]: (a.id, r) for a in base for r in a.requirements}
    after = {r["id"]: (a.id, r) for a in head for r in a.requirements}
    for rid in sorted(after.keys() - before.keys()):
        findings.error("V10", f"specs/{after[rid][0]}.zt adds requirement {rid}; new promises enter through an item")
    for rid in sorted(before.keys() - after.keys()):
        findings.error("V10", f"specs/{before[rid][0]}.zt removes requirement {rid}; supersede it from an item instead")
    for rid in sorted(before.keys() & after.keys()):
        if lib.canonical(before[rid][1]) != lib.canonical(after[rid][1]):
            findings.error("V10", f"specs/{after[rid][0]}.zt changes requirement {rid}; supersede it from an item instead")
    head_areas = {a.id: a for a in head}
    for area in base:
        new = head_areas.get(area.id)
        if new is None or lib.canonical(area.value["invariants"]) != lib.canonical(new.value["invariants"]):
            findings.needs_approval("V4", f"invariants of area {area.id} changed")


# --- Approvals ---------------------------------------------------------------


def review_agents() -> set[str]:
    return set(lib.names(lib.CODE / REVIEW_AGENTS))


def judge_approvals(findings: Findings, author: str, approvers: set[str], head_owners: set[str], reviewable: bool) -> None:
    """V4/V5 and V11: one independent review of the current head.

    A review is an approval from a person in HUMAN_OWNERS or from an account
    in REVIEW_AGENTS, as the judge's base lists them. It never counts from the
    author, from an owner this pull request adds, or from an account in
    AGENT_ACCOUNTS. V11 requires it of every `reviewable` pull request; V4 and
    V5 require it for each change that asked for an approval."""
    owners = lib.human_owners()
    if len(owners) < 2:
        findings.error("V4", f"HUMAN_OWNERS lists {len(owners)} person(s); at least two are needed so an author never approves alone")
    added = head_owners - owners
    excluded = {author} | lib.agent_accounts()
    valid = ((approvers & owners) - added - excluded) | ((approvers & review_agents()) - excluded)
    for reason in findings.approvals:
        print(f"approval: {reason}")
    if valid:
        print(f"review: satisfied by {sorted(valid)}")
        return
    rejected = sorted(approvers) or "none"
    who = f"other than the author {author or '(unknown)'}"
    if findings.approvals:
        findings.error("V4", f"{len(findings.approvals)} change(s) need an approval from HUMAN_OWNERS or REVIEW_AGENTS {who}; approvals on this head: {rejected}")
    if reviewable:
        findings.error("V11", f"this head has no independent review: an approval from HUMAN_OWNERS or REVIEW_AGENTS {who}; approvals on this head: {rejected}")
