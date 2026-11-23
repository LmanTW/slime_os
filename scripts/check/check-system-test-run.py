#!/usr/bin/env python3

"""Gate `contracts/system-test-run/v2`: execution inputs are declared, bounded, and typed.

CP11's boundary is that a marker oracle, a timeout, a disk fixture, or an
injected device event cannot alter the image closure it exercises. That
separation is only real if both halves are checked: the closure side by
`just system_image_closure_check`, and this side here.

What this asserts:

1. every plane gate that boots a seL4 QEMU image has a record, and every record
   names a plane gate — neither set may contain a name the other lacks;
2. each record decodes through the generated contract binding, so the bounds and
   closed vocabularies the schema declares are enforced rather than assumed;
3. a record naming a closure names the one its plane gate builds, and that
   closure exists and compiles; a record naming none corresponds to an image the
   aggregate gate independently agrees is closure-exempt — so an empty name is a
   checked statement rather than a blank field;
4. every declared timeout is positive and within the contract's ceiling, and
   every fault kind and execution kind is from the closed vocabulary;
5. the records agree with the checkers they were extracted from, which is what
   makes them a freeze rather than a snapshot that silently rots.

The records are declarations, not yet the execution path: the checkers still run
from their own constants, and CP15's migration is what makes these the input. The
freeze is what that migration will be verified against.
"""

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import importlib.util
import json
import re
import subprocess

from harness import ROOT
from zutai_cli import STDLIB, binary
from system_image_closure import (
    SystemImageClosureError,
    compile_test_run,
    compile_test_run_declaration,
)

RUN_ROOT = ROOT / "contracts" / "system-test-run" / "v2" / "runs"
CONTRACT = ROOT / "contracts" / "system-test-run" / "v2"
CLOSURE_ROOT = ROOT / "contracts" / "system-image-closure" / "v3" / "closures"
GENERATOR = ROOT / "scripts" / "generate" / "generate-system-test-runs.py"
AGGREGATE = ROOT / "scripts" / "check" / "check-system-image-aggregate.py"


def fail(message: str) -> None:
    raise SystemExit(f"system test run check: {message}")


def load(path: _Path):
    spec = importlib.util.spec_from_file_location(f"str_{path.stem.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR_MODULE = load(GENERATOR)


def aggregate_exempt_images() -> set[str]:
    """The images the aggregate gate declares closure-exempt.

    Read from that gate's source rather than by importing it: it runs its own
    assertions at import, and one gate silently executing another makes a
    failure attributable to the wrong checker.
    """
    text = AGGREGATE.read_text(encoding="utf-8")
    block = re.search(r"IMAGES_WITHOUT_CLOSURE = \{(.*?)\n\}", text, re.DOTALL)
    if block is None:
        fail("could not read the aggregate gate's exemption table")
    images = set(re.findall(r'"(slime-[a-z0-9.-]+\.elf)":', block.group(1)))
    if not images:
        fail("the aggregate gate's exemption table is empty, so no record may omit a closure")
    return images


def check_records_and_planes_correspond() -> int:
    """Every declared checker target has one record and no record is orphaned."""
    expected = {
        name
        for checker in GENERATOR_MODULE.plane_checkers()
        for name, _closure, _profile, _image in GENERATOR_MODULE.run_variants(checker)
    }
    present = {path.stem for path in RUN_ROOT.glob("*.zti")}
    if not expected:
        fail("no plane checker target was found, so this gate asserts nothing")
    missing = sorted(expected - present)
    if missing:
        fail(f"plane gate target(s) with no test-run record: {missing}")
    extra = sorted(present - expected)
    if extra:
        fail(f"test-run record(s) naming no plane gate target: {extra}")
    return len(present)


def decode(path: _Path) -> dict:
    """Decode one record through the contract, so schema bounds are enforced.

    Two steps, matching the convention every other contract gate here uses: the
    contract's own checker must answer `#valid`, and only then is the JSON
    projection read. Reading the projection alone would prove shape but not the
    bounds and closed vocabularies the schema declares.
    """
    import os

    environment = os.environ.copy()
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    environment["SLIME_SYSTEM_TEST_RUN_PATH"] = str(path)
    process = subprocess.run(
        [str(binary()), "run", str(CONTRACT / "check.zt")],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0 or not process.stdout.startswith("#valid"):
        detail = (process.stderr or process.stdout).strip()
        fail(f"{path.stem}: the contract refused this record: {detail}")
    process = subprocess.run(
        [str(binary()), "json", str(path)],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        fail(f"{path.stem}: invalid JSON projection: {(process.stderr or process.stdout).strip()}")
    return json.loads(process.stdout)


def path_json(path: _Path) -> str:
    """The record's JSON projection."""
    import os

    environment = os.environ.copy()
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    process = subprocess.run(
        [str(binary()), "json", str(path)],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        fail(f"{path.stem}: could not project to JSON: {(process.stderr or process.stdout).strip()}")
    return process.stdout


def contract_vocabulary() -> dict[str, set[str]]:
    """The closed vocabularies and ceilings the schema declares."""
    schema = (CONTRACT / "schema.zt").read_text(encoding="utf-8")
    execution = set(re.findall(r'^execution[A-Za-z]+ :: Text = "([a-z-]+)";', schema, re.MULTILINE))
    faults = set(re.findall(r'^fault[A-Za-z]+ :: Text = "([a-z-]+)";', schema, re.MULTILINE))
    ceiling = re.search(r"^maxTimeoutSeconds :: Int = (\d+);", schema, re.MULTILINE)
    fixtures = re.search(r"^maxFixtures :: Int = (\d+);", schema, re.MULTILINE)
    if not execution or not faults or ceiling is None or fixtures is None:
        fail("the schema declares no execution kind, fault kind, or ceiling to check against")
    return {
        "execution": execution,
        "faults": faults,
        "maxTimeout": {int(ceiling.group(1))},
        "maxFixtures": {int(fixtures.group(1))},
    }


def check_records(vocabulary: dict[str, set[str]]) -> tuple[int, int, int]:
    """Each record is typed, bounded, closed-vocabulary, and closure-consistent."""
    exempt_images = aggregate_exempt_images()
    from system_image_closure import compile_source

    closures = {path.stem for path in CLOSURE_ROOT.glob("*.zti")}
    compiled: set[str] = set()

    max_timeout = next(iter(vocabulary["maxTimeout"]))
    max_fixtures = next(iter(vocabulary["maxFixtures"]))
    resolved, exempt, faults = 0, 0, 0

    for path in sorted(RUN_ROOT.glob("*.zti")):
        record = decode(path)
        name = record["name"]
        if name != path.stem:
            fail(f"{path.stem}: declares name {name!r}, so the file and the record disagree")
        if record["formatVersion"] != 2:
            fail(f"{name}: declares format version {record['formatVersion']}, expected 2")
        if record["executionKind"] not in vocabulary["execution"]:
            fail(f"{name}: execution kind {record['executionKind']!r} is not in the vocabulary")

        timeout = record["timeoutSeconds"]
        if timeout <= 0:
            fail(f"{name}: declares a non-positive timeout, so its run would be unbounded")
        if timeout > max_timeout:
            fail(f"{name}: timeout {timeout} exceeds the contract ceiling {max_timeout}")

        for section in ("disks", "networks", "devices"):
            if len(record[section]) > max_fixtures:
                fail(f"{name}: declares more {section} than the contract admits")
            for fixture in record[section]:
                if not fixture["name"]:
                    fail(f"{name}: a {section} fixture has no name")

        for control in record["faultControls"]:
            if control["kind"] not in vocabulary["faults"]:
                fail(f"{name}: fault kind {control['kind']!r} is not in the vocabulary")
            faults += 1

        named = record["imageClosure"]
        matches = [
            (checker, closure, profile, image)
            for checker in GENERATOR_MODULE.plane_checkers()
            for variant_name, closure, profile, image in GENERATOR_MODULE.run_variants(checker)
            if variant_name == name
        ]
        if len(matches) != 1:
            fail(f"{name}: resolves to {len(matches)} checker targets, expected exactly one")
        checker, expected_closure, expected_profile, expected_image = matches[0]
        if record["executionProfile"] != expected_profile:
            fail(
                f"{name}: execution profile {record['executionProfile']!r} differs from "
                f"its checker's declared {expected_profile!r}"
            )
        if named:
            if named not in closures:
                fail(f"{name}: names closure {named!r}, which does not exist")
            if named != expected_closure:
                fail(
                    f"{name}: names the closure {named!r}, but its own "
                    f"checker target declares closure {expected_closure!r}"
                )
            if named not in compiled:
                try:
                    compile_source(CLOSURE_ROOT / f"{named}.zti")
                except SystemImageClosureError as error:
                    fail(f"{name}: names closure {named!r}, which does not compile: {error}")
                compiled.add(named)
            resolved += 1
        else:
            image = expected_image
            if image not in exempt_images:
                fail(
                    f"{name}: names no closure, but {image} is not one the aggregate gate "
                    "declares closure-exempt"
                )
            exempt += 1

        try:
            compile_test_run_declaration(path)
        except SystemImageClosureError as error:
            fail(f"{name}: invalid frozen declaration: {error}")

    return resolved, exempt, faults


def check_records_match_their_checkers() -> None:
    """The freeze holds: no record drifted from the gate it was extracted from."""
    process = subprocess.run(
        ["python3", str(GENERATOR), "--check"],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if process.returncode != 0:
        fail(f"records disagree with their checkers:\n{process.stdout.strip()}")


def check_controls(vocabulary: dict[str, set[str]]) -> int:
    """This gate refuses each drift it claims to catch."""
    import copy
    import tempfile

    template = json.loads(path_json(RUN_ROOT / "sel4-channel.zti"))
    controls = [
        ("an unadmitted execution kind", {"executionKind": "hypervisor"}, "not in the vocabulary"),
        ("a zero timeout", {"timeoutSeconds": 0}, "unbounded"),
        (
            "a timeout beyond the contract ceiling",
            {"timeoutSeconds": next(iter(vocabulary["maxTimeout"])) + 1},
            "exceeds the contract ceiling",
        ),
        (
            "a closure that does not exist",
            {"imageClosure": "sel4-no-such-closure"},
            "which does not exist",
        ),
        (
            "another plane's closure",
            {"imageClosure": "sel4-zenoh"},
            "checker target declares closure",
        ),
        (
            "an unadmitted fault kind",
            {"faultControls": [{"kind": "ambient", "target": "x", "value": "y"}]},
            "is not in the vocabulary",
        ),
    ]
    refused = 0
    for label, patch, needle in controls:
        value = copy.deepcopy(template)
        value.update(patch)
        with tempfile.TemporaryDirectory(prefix="slime-test-run-control-") as scope:
            scratch = _Path(scope) / "runs"
            scratch.mkdir()
            for path in RUN_ROOT.glob("*.zti"):
                (scratch / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            (scratch / "sel4-channel.zti").write_text(
                GENERATOR_MODULE.render(
                    value["name"],
                    value["imageClosure"],
                    value["executionProfile"],
                    {
                        "timeoutSeconds": value["timeoutSeconds"],
                        "drives": len(value["disks"]),
                        "devices": [device["name"] for device in value["devices"]],
                        "forbiddenOutcomes": value["forbiddenOutcomes"],
                        "faults": [control["kind"] for control in value["faultControls"]],
                    },
                ).replace('executionKind = "emulator"', f'executionKind = "{value["executionKind"]}"'),
                encoding="utf-8",
            )
            try:
                _check_scratch(scratch, vocabulary)
            except SystemExit as error:
                if needle not in str(error):
                    fail(f"control {label!r} failed for the wrong reason: {error}")
                refused += 1
            else:
                fail(f"control {label!r} was accepted, so this gate does not catch it")
    return refused


def _check_scratch(scratch: _Path, vocabulary: dict[str, set[str]]) -> None:
    """Run the record assertions against a scratch directory."""
    global RUN_ROOT
    saved = RUN_ROOT
    RUN_ROOT = scratch
    try:
        check_records(vocabulary)
    finally:
        RUN_ROOT = saved


def check_declaration_controls() -> int:
    """Placeholders are declarations only, and a closure is named, never digested."""
    import tempfile

    template = json.loads(path_json(RUN_ROOT / "sel4-channel.zti"))
    # Use the existing generator's inert-data renderer, without its placeholder synthesis.
    renderer = load(ROOT / "scripts/generate/generate-generation-from-spec.py").zti
    fixture = {"name": "disk-0", "path": "", "identity": "", "writable": True}
    fault = {"kind": "delay", "target": "", "value": ""}
    refused = 0
    with tempfile.TemporaryDirectory(prefix="slime-run-declaration-") as directory:
        root = _Path(directory)
        path = root / "sel4-channel.zti"

        def write(value: dict) -> None:
            path.write_text(renderer(value) + "\n", encoding="utf-8")

        for patch in (
            {"disks": [fixture]}, {"faultControls": [fault]}, {"imageClosure": ""},
        ):
            value = template | patch
            write(value)
            compile_test_run_declaration(path)
            try:
                compile_test_run(path)
            except SystemImageClosureError:
                refused += 1
            else:
                fail("unbound declaration admitted as executable test-run input")

        for patch in (
            {"disks": [fixture | {"path": "disk.raw"}]},
            {"disks": [fixture | {"identity": "a" * 64}]},
            {"disks": [fixture | {"path": "disk.raw", "identity": "invalid"}]},
            {"faultControls": [fault | {"target": "peer"}]},
            {"faultControls": [fault | {"value": "1"}]},
            {"disks": [fixture, fixture]},
            {"imageClosure": "Not A Closure"},
            {"imageClosure": "a" * 64},
        ):
            write(template | patch)
            try:
                compile_test_run_declaration(path)
            except SystemImageClosureError:
                refused += 1
            else:
                fail("malformed or partially bound declaration accepted")

        bound = template | {
            "disks": [fixture | {"path": "disk.raw", "identity": "a" * 64}],
            "faultControls": [fault | {"target": "peer", "value": "1"}],
        }
        write(bound)
        if compile_test_run(path).identity != compile_test_run_declaration(path).identity:
            fail("bound declaration and strict input have different content identities")

        checker = root / "check-sel4-private-memory-plane.py"
        checker.write_text('TIMEOUT = 240\n', encoding="utf-8")
        try:
            GENERATOR_MODULE.extract(checker)
        except SystemExit as error:
            if "adaptive-only transport declaration" not in str(error):
                raise
            refused += 1
        else:
            fail("missing adaptive-only transport boundary was accepted")
        checker.write_text('TIMEOUT = 240\nADAPTIVE_DEVICE_ARGUMENTS = ()\n')
        base = GENERATOR_MODULE.extract(checker)
        checker.write_text(
            'TIMEOUT = 240\nADAPTIVE_DEVICE_ARGUMENTS: tuple[str, ...] = (\n'
            '    "-drive", "if=none,file=/dev/zero",\n'
            '    "-device", "virtio-blk-device,drive=d0",\n)\n',
            encoding="utf-8",
        )
        if GENERATOR_MODULE.extract(checker) != base:
            fail("adaptive-only transport changed fixed-memory declarations")
        checker.write_text(checker.read_text().replace(': tuple[str, ...]', ''))
        if GENERATOR_MODULE.extract(checker) != base:
            fail("unannotated adaptive-only transport changed fixed-memory declarations")
        checker.write_text(checker.read_text() + 'FIXED_ARGS = ("-drive",)\n')
        if GENERATOR_MODULE.extract(checker)["drives"] != 1:
            fail("fixed-memory transport was hidden with the adaptive-only arguments")
    return refused


def check_inventory_controls() -> int:
    """Exercise real inventory/extraction with isolated files, without boot claims."""
    import copy
    import tempfile
    from unittest.mock import patch

    import work_items

    generator = GENERATOR_MODULE
    if not isinstance(getattr(generator, "PLANNED_RUNS", None), dict):
        fail("inventory controls require the planned-run registry implementation")
    required = {
        "sel4-entropy": (
            "01a0ec3a-a91f-7349-a28a-26a60d8d7f4e",
            "check-sel4-entropy-plane.py",
            ("components/services/virtio-rng-driver", "components/services/entropy-service"),
        ),
        "sel4-large-image": (
            "01a0fa78-cfc0-7dc0-976e-3ff092b908a4",
            "check-sel4-reclamation-plane.py",
            tuple(f"components/testkit/large-image-{role}" for role in ("owner", "probe", "witness")),
        ),
    }
    registry = {}
    for run, (item, checker, crates) in required.items():
        mandatory = {
            f"contracts/system-spec/v1/systems/{run}.zti",
            f"contracts/generation-manifest/v1/compositions/{run}.zti",
            f"contracts/system-image-closure/v3/closures/{run}.zti",
            f"contracts/system-test-run/v2/runs/{run}.zti",
            *crates,
        }
        registry[run] = (item, checker, run, tuple(sorted(mandatory)))
        row = generator.PLANNED_RUNS.get(run)
        if row is None and (CLOSURE_ROOT / f"{run}.zti").is_file():
            continue
        if not isinstance(row, tuple) or len(row) != 4 or row[:3] != (item, checker, run):
            fail(f"inventory control: {run} lacks its canonical planning registration")
        if not mandatory <= set(row[3]):
            fail(f"inventory control: {run} omits required implementation artifacts")

    refused = 0

    def refuse(label, operation) -> None:
        nonlocal refused
        try:
            operation()
        except SystemExit as error:
            if "system test run generation:" not in str(error):
                fail(f"inventory control {label}: wrong refusal: {error}")
            refused += 1
        else:
            fail(f"inventory control accepted {label}")

    with tempfile.TemporaryDirectory(prefix="slime-run-inventory-") as directory:
        root = _Path(directory)
        checkers = root / "scripts/check"
        closures = root / "contracts/system-image-closure/v3/closures"
        runs = root / "contracts/system-test-run/v2/runs"
        items = root / ".tasks/items"
        for path in (checkers, closures, runs, items):
            path.mkdir(parents=True)
        terminal = root / ".tasks/terminal"
        terminal.mkdir(parents=True)

        def run_slug(identity: str) -> str:
            return f"planned-{identity[:8]}"

        def planning_item(identity: str, intent: str | None) -> str:
            # The task/v2 head the shared reader keys on; no intent means #planned.
            field = f"    intent = #{intent};\n" if intent else ""
            return (f'item :: s.Item = (h.task "{identity}" "{run_slug(identity)}" "quality" "t" "p")\n'
                    f"  with {{\n{field}  }};\n")

        for item, checker, _crates in required.values():
            (checkers / checker).write_bytes((ROOT / "scripts/check" / checker).read_bytes())
            (items / f"{run_slug(item)}.zt").write_text(planning_item(item, None))
        closure_source = (CLOSURE_ROOT / "sel4-reclamation-unwind.zti").read_text()
        (closures / "sel4-reclamation-unwind.zti").write_text(closure_source)
        local_registry = {run: registry[run] for run in required}
        with (
            patch.multiple(generator, ROOT=root, CHECK_ROOT=checkers, CLOSURE_ROOT=closures,
                           RUN_ROOT=runs, PLANNED_RUNS=local_registry),
            patch.multiple(work_items, ROOT=root, TASKS=root / ".tasks", ITEMS=items,
                           TERMINAL=terminal, LEGACY=root / "specs/legacy.zt"),
        ):
            work_items.cache_clear()
            try:
                reclamation = checkers / "check-sel4-reclamation-plane.py"
                entropy = checkers / "check-sel4-entropy-plane.py"
                expected = [("sel4-reclamation", "sel4-reclamation-unwind", "qemu-arm-virt", "")]
                if generator.run_variants(reclamation) != expected or generator.run_variants(entropy):
                    fail("inventory control: planning suppression hid a live arm or admitted a planned arm")
                emitted = generator.outputs()
                if set(emitted) != {runs / "sel4-reclamation.zti"}:
                    fail("inventory control: planned declarations leaked into outputs")
                active_closure = closures / "sel4-reclamation-unwind.zti"
                active_closure.unlink()
                refuse("missing active unwind closure", generator.outputs)
                active_closure.write_text(closure_source)
                if generator.outputs() != emitted:
                    fail("inventory control: restoring active closure did not restore inventory")
                unknown = checkers / "check-sel4-unregistered-plane.py"
                unknown.write_text('CLOSURE = "sel4-unregistered"\nTIMEOUT = 180\n')
                refuse("unregistered missing closure", generator.outputs)
                unknown.unlink()

                row = local_registry["sel4-entropy"]
                for label, replacement in (
                    ("display alias", ("IO-ENTROPY", *row[1:])),
                    ("unknown identity", ("00000000-0000-7000-8000-000000000000", *row[1:])),
                    ("missing checker", (row[0], "check-sel4-missing-plane.py", *row[2:])),
                    ("wrong closure", (*row[:2], "sel4-wrong", row[3])),
                    ("empty artifacts", (*row[:3], ())),
                    ("absolute artifact", (*row[:3], (*row[3], "/outside"))),
                    ("escaping artifact", (*row[:3], (*row[3], "../outside"))),
                    ("omitted closure", (*row[:3], tuple(p for p in row[3] if "system-image-closure" not in p))),
                    ("omitted run", (*row[:3], tuple(p for p in row[3] if "system-test-run" not in p))),
                ):
                    with patch.dict(local_registry, {"sel4-entropy": replacement}):
                        refuse(label, generator.outputs)
                    if generator.outputs() != emitted:
                        fail(f"inventory control {label}: restoring registration did not restore inventory")
                with patch.dict(local_registry, {"sel4-unknown": row}):
                    refuse("registration naming no declared run", generator.outputs)
                with patch.object(generator, "NOT_A_PLANE", generator.NOT_A_PLANE | {row[1]}):
                    refuse("planning registration conflicts with non-plane classification", generator.outputs)
                for run, registration in local_registry.items():
                    for artifact in registration[3]:
                        path = root / artifact
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("present\n")
                        refuse(f"stale {run} registration at {artifact}", generator.outputs)
                        path.unlink()
                item_path = items / f"{run_slug(row[0])}.zt"
                closed_path = terminal / item_path.name
                for intent in ("active", "blocked", "deferred"):
                    item_path.write_text(planning_item(row[0], intent))
                    work_items.cache_clear()
                    if generator.outputs() != emitted:
                        fail(f"inventory control: explicit planning registration lost in {intent} intent")
                for intent in ("cancelled", "invalid"):
                    item_path.write_text(planning_item(row[0], intent))
                    work_items.cache_clear()
                    refuse(f"{intent} planning identity", generator.outputs)
                item_path.unlink()
                closed_path.write_text(planning_item(row[0], "active"))
                work_items.cache_clear()
                refuse("done planning identity", generator.outputs)
                closed_path.unlink()
                item_path.write_text(planning_item(row[0], None))
                work_items.cache_clear()

                source = reclamation.read_text()
                unwind = generator.extract(reclamation, "sel4-reclamation")
                large = generator.extract(reclamation, "sel4-large-image")
                for facts in (unwind, large):
                    if facts["drives"] != 0 or facts["devices"] or facts["faults"]:
                        fail("inventory control: host controls contaminated runtime execution facts")
                if unwind["timeoutSeconds"] != 180 or large["timeoutSeconds"] != 1800:
                    fail("inventory control: arm timeouts are not independently 180/1800")
                if unwind["forbiddenOutcomes"] != []:
                    fail("inventory control: unwind no longer matches its frozen forbidden outcomes")
                if large["forbiddenOutcomes"] != ["SLIME_GRAPH FAIL", "SLIME_ROOT FATAL"]:
                    fail("inventory control: large-image forbidden outcomes differ from its own declarations")
                refuse("unknown extraction arm", lambda: generator.extract(reclamation, "sel4-unknown"))
                reclamation.write_text(source.replace("TIMEOUT = 180\n", "TIMEOUT = 181\n", 1))
                if generator.extract(reclamation, "sel4-reclamation") != (unwind | {"timeoutSeconds": 181}):
                    fail("inventory control: unwind extraction ignored its own timeout change")
                if generator.extract(reclamation, "sel4-large-image") != large:
                    fail("inventory control: unwind timeout contaminated large-image")
                changed = source.replace("LARGE_TIMEOUT = 1800", "LARGE_TIMEOUT = 1900").replace(
                    'LARGE_FAILURES = (', 'LARGE_FAILURES = (\n    r"SLIME_ROOT PANIC",')
                if changed == source:
                    fail("inventory control did not mutate large-arm declarations")
                reclamation.write_text(changed)
                if generator.extract(reclamation, "sel4-reclamation") != unwind:
                    fail("inventory control: large-arm changes altered unwind execution facts")
                changed_large = copy.deepcopy(large)
                changed_large["timeoutSeconds"] = 1900
                changed_large["forbiddenOutcomes"] = sorted(set(large["forbiddenOutcomes"]) | {"SLIME_ROOT PANIC"})
                if generator.extract(reclamation, "sel4-large-image") != changed_large:
                    fail("inventory control: large-arm extraction ignored its own changes")
                reclamation.write_text(source)

                # Landing an implementation retires its planning registration first.
                large_row = local_registry.pop("sel4-large-image")
                refuse("implemented arm missing its closure", generator.outputs)
                for artifact in large_row[3]:
                    path = root / artifact
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("implemented fixture\n")
                (closures / "sel4-large-image.zti").write_text(
                    closure_source.replace('name = "sel4-reclamation-unwind";', 'name = "sel4-large-image";', 1))
                outputs = generator.outputs()
                expected_paths = {runs / "sel4-reclamation.zti", runs / "sel4-large-image.zti"}
                if set(outputs) != expected_paths:
                    fail("inventory control: implemented large arm did not acquire exactly one record")
                for path, content in outputs.items():
                    path.write_text(content)
                    record = compile_test_run_declaration(path)
                    if not record.identity:
                        fail("inventory control: emitted declaration has no identity")
                if 'timeoutSeconds = 180;' not in outputs[runs / "sel4-reclamation.zti"] or 'timeoutSeconds = 1800;' not in outputs[runs / "sel4-large-image.zti"]:
                    fail("inventory control: outputs did not pass the run selector to extraction")
                with patch.dict(globals(), {"RUN_ROOT": runs}):
                    if check_records_and_planes_correspond() != 2:
                        fail("inventory control: checker discovery disagrees with generator")
                    missing = runs / "sel4-large-image.zti"
                    missing.unlink()
                    try:
                        check_records_and_planes_correspond()
                    except SystemExit as error:
                        if "no test-run record" not in str(error):
                            raise
                        refused += 1
                    else:
                        fail("inventory control: checker accepted missing active declaration")
                    missing.write_text(outputs[missing])
                    orphan = runs / "sel4-orphan.zti"
                    orphan.write_text(outputs[missing])
                    try:
                        check_records_and_planes_correspond()
                    except SystemExit as error:
                        if "naming no plane gate" not in str(error):
                            raise
                        refused += 1
                    else:
                        fail("inventory control: checker accepted orphan declaration")
                    orphan.unlink()
                reclamation.write_text(changed)
                if generator.outputs() == outputs:
                    fail("inventory control: an execution change to an arm left its declaration unchanged")
            finally:
                work_items.cache_clear()
    return refused


# The network checker boots one image per arm. The generator declares each arm's devices in `ARM_DEVICES`, and
# this gate checks that declaration against the checker's code in both directions.
NETWORK_CHECKER = "check-sel4-io-network-plane.py"


def built_closures(checker: _Path) -> set[str]:
    """Every closure a checker passes to `build_image`, read by the generator, which refuses any other use of the name."""
    return GENERATOR_MODULE.built_closures(checker)


def check_arm_controls() -> int:
    """The network checker's arms are each recorded, and the code agrees with the devices the tables declare."""
    import tempfile
    from unittest.mock import patch

    generator = GENERATOR_MODULE
    checker = generator.CHECK_ROOT / NETWORK_CHECKER
    refused = 0
    declared = generator.ARM_DEVICES[NETWORK_CHECKER]

    def refuse(label, operation) -> None:
        nonlocal refused
        try:
            operation()
        except SystemExit as error:
            if not str(error).startswith(("system test run generation:", "system test run check:")):
                fail(f"arm control {label}: wrong refusal: {error}")
            refused += 1
        else:
            fail(f"arm control accepted {label}")

    variants = {name: closure for name, closure, _profile, _image in generator.run_variants(checker)}
    planned = {name: row[2] for name, row in generator.PLANNED_RUNS.items() if row[1] == NETWORK_CHECKER}
    if set(variants) | set(planned) != set(declared) or set(variants) & set(planned):
        fail(f"arm control: the checker declares {sorted((set(variants) | set(planned)) ^ set(declared))} beyond or short of ARM_DEVICES")
    if {*variants.values(), *planned.values()} != built_closures(checker):
        fail(
            "arm control: the closures the network checker builds differ from the runs it declares: "
            f"{sorted({*variants.values(), *planned.values()} ^ built_closures(checker))}"
        )
    for name in sorted({*variants, *planned}):
        facts = generator.extract(checker, name)
        if facts["devices"] != sorted(declared[name]) or facts["drives"] != 0 or facts["faults"] or facts["timeoutSeconds"] != 240:
            fail(f"arm control: {name} extracts {facts}, expected devices {sorted(declared[name])}, no drives, no faults and 240 s")
        if name in planned:
            if (RUN_ROOT / f"{name}.zti").exists():
                fail(f"arm control: {name} is planned and already has a run record")
        elif not (RUN_ROOT / f"{name}.zti").is_file():
            fail(f"arm control: {name} has no run record")
    if sum(1 for devices in declared.values() if devices) != 10 or sum(1 for devices in declared.values() if not devices) != 6:
        fail("arm control: the network checker no longer has ten NIC arms and six arms with no device")

    source = checker.read_text(encoding="utf-8")

    def mutated(old: str, new: str) -> str:
        if source.count(old) != 1:
            fail(f"arm control: the text it mutates appears {source.count(old)} times in the checker, not once")
        return source.replace(old, new)

    pair = '("-device", "virtio-rng-device")'
    auth = "def run_authority_arm(image: Path) -> None:\n"
    peer = "    peer = link_peer.Peer(hold_first_tcp=driver_reset)\n"
    top = "TIMEOUT = 240\n"
    impair = "def run_impairment_arm(image: Path, mac: str, retry_limits: dict[int, int], transcript_path: Path | None) -> None:\n"
    helper = f"\n\ndef boot_rng(image):\n    return {pair}\n"

    def with_top(lines: str, use: str = "") -> str:
        return mutated(top, top + lines).replace(impair, impair + use, 1)

    with tempfile.TemporaryDirectory(prefix="slime-arm-controls-") as directory:
        copy = _Path(directory) / NETWORK_CHECKER

        def refused_edit(label: str, text: str, arm: str = "sel4-io-tcp-impairment") -> None:
            copy.write_text(text, encoding="utf-8")
            compile(text, label, "exec")
            refuse(label, lambda: generator.extract(copy, arm))

        # Code that passes a QEMU token anywhere but in a declared site is refused, whatever its shape. The
        # arm does not matter, because the placement check runs before any arm is read.
        for label, text in (
            ("a device pair in the authority arm", mutated(auth, auth + f"    extra = {pair}\n")),
            ("a single-quoted device pair", mutated(auth, auth + "    extra = ('-device', 'virtio-rng-device')\n")),
            ("a triple-quoted device name", mutated(auth, auth + '    extra = ("-device", """virtio-rng-device""")\n')),
            ("an additional_arguments keyword", mutated("        pins_path=PINS,\n    )\n    match_marker_contract(transcript, AUTHORITY_CHAINS", "        pins_path=PINS,\n        additional_arguments=('-device', 'virtio-rng-device'),\n    )\n    match_marker_contract(transcript, AUTHORITY_CHAINS")),
            ("a device name completed by an f-string", mutated(auth, auth + '    extra = ("-device", f"virtio-{kind}-device")\n')),
            ("a device name whose prefix is a value", mutated(auth, auth + '    prefix = "virtio"\n    extra = ("-device", f"{prefix}-rng-device")\n')),
            ("a device name built by concatenation", mutated(auth, auth + '    extra = ("-device", "virtio-" + kind + "-device")\n')),
            ("a device name built by formatting", mutated(auth, auth + '    extra = ("-device", "virtio-%s-device" % kind)\n')),
            ("a module tuple read by an arm", with_top(f"EXTRA_DEVICE = {pair}\n", "    extra = EXTRA_DEVICE\n")),
            ("a module tuple read through another module name", with_top(f"BASE_DEVICE = {pair}\nEXTRA_DEVICE = BASE_DEVICE\n", "    extra = EXTRA_DEVICE\n")),
            ("a module tuple that no arm reads", with_top(f"UNUSED_DEVICE = {pair}\n")),
            ("a destructured pair", with_top('ARG, DEV = "-device", "virtio-rng-device"\n', "    extra = (ARG, DEV)\n")),
            ("a star target", with_top('ARG, *REST = "-device", "virtio-rng-device"\n', "    extra = (ARG, REST)\n")),
            ("a module-level walrus", with_top(f"(WALRUS := {pair})\n", "    extra = WALRUS\n")),
            ("an augmented assignment", with_top(f"EXTRA_DEVICE = ()\nEXTRA_DEVICE += {pair}\n", "    extra = EXTRA_DEVICE\n")),
            ("a class attribute", with_top(f"class Config:\n    DEVICE = {pair}\n", "    extra = Config.DEVICE\n")),
            ("a dict literal", with_top(f'CONFIG = {{"device": {pair}}}\n', '    extra = CONFIG["device"]\n')),
            ("a module-level lambda", with_top(f"MAKE_DEVICE = lambda: {pair}\n", "    extra = MAKE_DEVICE()\n")),
            ("a drive token at module level", with_top('DRIVE = ("-drive", "file=x")\n')),
            ("a usb-kbd token at module level", with_top('KEYBOARD = "usb-kbd"\n')),
            ("additional_arguments bound at module level", with_top("additional_arguments = ()\n")),
            ("a function that no arm runs and that holds a device", source + helper),
            ("an uncalled nested function holding a device", mutated(auth, auth + f"    def helper():\n        return {pair}\n")),
            ("a called nested function holding a device", mutated(auth, auth + f"    def helper():\n        return {pair}\n    helper()\n")),
            ("a nested lambda holding a device", mutated(auth, auth + f"    helper = lambda: {pair}\n")),
            ("a nested class holding a device", mutated(auth, auth + f"    class Local:\n        device = {pair}\n")),
            ("a helper called under a flag conditional", mutated(peer, peer + "    held = boot_rng(None) if driver_reset else None\n") + helper),
            ("a helper called by an uncalled nested function", mutated(auth, auth + "    def never_called():\n        return boot_rng(None)\n") + helper),
        ):
            refused_edit(label, text)

        # A declared site must pass exactly the devices it declares. A device added to a site, a device removed
        # from it, and a second device are refused, whichever arm is read.
        site = mutated('"-device", f"virtio-net-device,netdev=slimenet,mac={mac}",', '"-device", f"virtio-net-device,netdev=slimenet,mac={mac}", "-device", "virtio-rng-device",')
        refused_edit("a second device added to a declared site", site, "sel4-net")
        refused_edit(
            "the device removed from a declared site",
            mutated('"-device", f"virtio-net-device,netdev=slimenet,mac={mac}",\n                    "-object", f"filter-dump,id=netcapture,netdev=slimenet,file={capture}",\n                ),\n                input_steps',
                    '"-object", f"filter-dump,id=netcapture,netdev=slimenet,file={capture}",\n                ),\n                input_steps'),
            "sel4-net",
        )
        refused_edit("a device name swapped in a declared site", mutated('f"virtio-net-device,netdev=slimenet,mac={mac}"', 'f"virtio-rng-device,netdev=slimenet,mac={mac}"'), "sel4-net")

        # Each argument of a site is read where it is written. A second device of the same model, a pair moved
        # into a nested helper, and a value that is not a device literal are refused, so a count over the whole
        # function and a decoy literal elsewhere in it cannot satisfy the declaration.
        net = '"-device", f"virtio-net-device,netdev=slimenet,mac={mac}",'
        peer_pair = '"-device",\n                f"virtio-net-device,netdev=slimelink,mac={mac}",'
        net_head = "def run_net_arm(image: Path, mac: str, transcript_path: Path | None) -> None:\n"
        refused_edit("a second identical NIC in a site", mutated(net, net + " " + net), "sel4-net")
        refused_edit("a second identical NIC in the peer site", mutated(peer_pair, peer_pair + "\n                " + peer_pair), "sel4-io-tcp")
        refused_edit(
            "an existing device pair moved into a nested helper inside its site",
            mutated(net, "*helper_args(mac),").replace(net_head, net_head + '    def helper_args(mac):\n        return ("-device", f"virtio-net-device,netdev=slimenet,mac={mac}")\n', 1),
            "sel4-net",
        )
        refused_edit("a device value computed beside a decoy literal", mutated(net, '"-device", f"{prefix}-{kind}", "-comment", "virtio-net-device",'), "sel4-net")
        refused_edit("a device value that is a variable beside a decoy literal", mutated(net, '"-device", chosen, "-comment", "virtio-net-device",'), "sel4-net")
        refused_edit("a device value built by concatenation beside a decoy literal", mutated(net, '"-device", "virtio-" + kind + "-device", "-comment", "virtio-net-device",'), "sel4-net")
        refused_edit("a device whose name is a prefix value in an f-string", mutated(net, '"-device", f"{prefix}-net-device,netdev=slimenet",'), "sel4-net")
        refused_edit(
            "a -device that ends the arguments",
            mutated('"-object", f"filter-dump,id=netcapture,netdev=slimenet,file={capture}",\n                ),\n                input_steps', '"-device",\n                ),\n                input_steps').replace(net, '"-netdev", netdev,', 1),
            "sel4-net",
        )
        refused_edit("a starred element in the arguments", mutated(net, "*extra_arguments,"), "sel4-net")
        refused_edit("a flag the generator does not record", mutated(net, net + ' "-drive", "file=x",'), "sel4-net")
        refused_edit("a serial flag the generator does not record", mutated(net, net + ' "-serial", "null",'), "sel4-net")
        refused_edit(
            "additional_arguments that is a variable",
            mutated("        timeout=TIMEOUT,\n        terminal_condition=terminal,\n        fail=fail,\n        pins_path=PINS,\n    )\n    match_marker_contract(transcript, AUTHORITY_CHAINS", "        timeout=TIMEOUT,\n        terminal_condition=terminal,\n        fail=fail,\n        pins_path=PINS,\n        additional_arguments=held_arguments,\n    )\n    match_marker_contract(transcript, AUTHORITY_CHAINS"),
        )

        # An arm reaches a site by any name it reads, and its declared devices must equal what its sites attach.
        # A site that an arm newly reaches changes what it attaches, so the declaration must change with it.
        refused_edit("a NIC site reached by an arm that declares none", mutated(auth, auth + "    run_net_arm\n"), "sel4-io-network")
        refused_edit("a NIC site passed as a value to an arm that declares none", mutated(auth, auth + "    held = [run_net_arm]\n"), "sel4-io-network")
        refused_edit("a NIC site reached through an alias", mutated(auth, auth + "    held = run_net_arm\n    held\n"), "sel4-io-network")
        refused_edit("a NIC site reached only from a nested function", mutated(auth, auth + "    def later():\n        return run_net_arm\n"), "sel4-io-network")
        refused_edit("a NIC site reached only in a branch of a conditional", mutated(auth, auth + "    held = run_net_arm if image else None\n"), "sel4-io-network")
        refused_edit("a helper that reaches a NIC site, read by an arm with none", mutated(auth, auth + "    run_helper_new\n") + "\n\ndef run_helper_new():\n    return run_net_arm\n", "sel4-io-network")
        copy.write_text(source, encoding="utf-8")
        for label, arm, table in (
            ("an arm whose declaration lacks a device its sites attach", "sel4-net", {"sel4-net": ()}),
            ("an arm whose declaration adds a device its sites do not attach", "sel4-io-network", {"sel4-io-network": ("virtio-net-device",)}),
            ("an arm whose declaration names the wrong device", "sel4-net", {"sel4-net": ("virtio-rng-device",)}),
        ):
            with patch.dict(generator.ARM_DEVICES, {NETWORK_CHECKER: {**declared, **table}}):
                refuse(label, lambda arm=arm: generator.extract(copy, arm))
        with patch.dict(generator.ARM_DEVICES, {NETWORK_CHECKER: {key: value for key, value in declared.items() if key != "sel4-http"}}):
            refuse("an arm in the entry table with no device declaration", lambda: generator.extract(copy, "sel4-http"))
        with patch.dict(generator.QEMU_SITES, {NETWORK_CHECKER: {**generator.QEMU_SITES[NETWORK_CHECKER], "run_nothing": ("virtio-net-device",)}}):
            refuse("a site that the checker does not define", lambda: generator.extract(copy, "sel4-net"))
        with patch.dict(generator.QEMU_SITES, {NETWORK_CHECKER: {key: value for key, value in generator.QEMU_SITES[NETWORK_CHECKER].items() if key != "run_http_request"}}):
            refuse("a site that holds QEMU tokens and is not declared", lambda: generator.extract(copy, "sel4-http"))

        # Only a call to run_plane adds additional_arguments to QEMU, so the keyword is read from that call alone.
        # A flag that is not a literal, a value that is not a name, a literal or an f-string, and a launcher that is
        # reached in any way but a direct call are refused, because what they pass cannot be read from the source.
        plane_tail = "                input_steps=steps, input_character_delay=0.005,\n            )"
        moved_nic = (
            '                additional_arguments=(),\n' + plane_tail + '\n            metadata = {}\n'
            '            metadata.update(additional_arguments=("-netdev", netdev, "-device", f"virtio-net-device,netdev=slimenet,mac={mac}"))'
        )
        refused_edit(
            "the NIC tuple moved to a call that is not run_plane",
            mutated(
                '                additional_arguments=(\n                    "-netdev", netdev,\n                    "-device", f"virtio-net-device,netdev=slimenet,mac={mac}",\n'
                '                    "-object", f"filter-dump,id=netcapture,netdev=slimenet,file={capture}",\n                ),\n' + plane_tail,
                moved_nic,
            ),
            "sel4-net",
        )
        peer_pair = '"-device",\n                f"virtio-net-device,netdev=slimelink,mac={mac}",'
        for label, addition in (
            ('a flag built by concatenation', '"-" + "device",\n                "virtio-rng-device",'),
            ("a flag built by an f-string", 'f"-{kind}",\n                "virtio-rng-device",'),
            ("a flag that is a variable", 'flag,\n                "virtio-rng-device",'),
            ("an odd number of elements", "str(3),"),
        ):
            refused_edit(f"{label} after a declared device", mutated(peer_pair, peer_pair + "\n                " + addition), "sel4-io-tcp")
        net_pairs = '"-netdev", netdev,\n                    "-device", f"virtio-net-device,netdev=slimenet,mac={mac}",'
        for label, value in (
            ("a -netdev value that is a call", "build_netdev()"),
            ("a -netdev value that is a number", "3"),
            ("a -netdev value that is an attribute", "settings.netdev"),
            ("a -netdev value that is a flag", '"-device"'),
            ("a -netdev value that is an f-string starting with a flag", 'f"-device {kind}"'),
        ):
            refused_edit(label, mutated(net_pairs, net_pairs.replace("netdev,\n", value + ",\n", 1)), "sel4-net")
        # Every run_plane call in a site must carry additional_arguments, and every launch path of a site must
        # attach the same devices, so a path that attaches nothing cannot hide behind the path that attaches a NIC.
        peer_call = "        transcript = run_plane(\n            image=image,\n            timeout=TIMEOUT,\n            terminal_condition=terminal,\n            fail=fail,\n            pins_path=PINS,\n            additional_arguments=("
        early = "        if peer is not None:\n            return run_plane(image=image, timeout=TIMEOUT, terminal_condition=terminal, fail=fail, pins_path=PINS)\n"
        refused_edit("an early run_plane in a site with no additional_arguments", mutated(peer_call, early + peer_call), "sel4-io-tcp")
        refused_edit(
            "an early run_plane in a site with an empty additional_arguments",
            mutated(peer_call, early.replace("pins_path=PINS)", "pins_path=PINS, additional_arguments=())") + peer_call),
            "sel4-io-tcp",
        )
        refused_edit(
            "a second launch path in a site with a different device",
            mutated(peer_call, early.replace("pins_path=PINS)", 'pins_path=PINS, additional_arguments=("-device", "virtio-rng-device"))') + peer_call),
            "sel4-io-tcp",
        )
        refused_edit(
            "a launch path in a site that gives additional_arguments as a name",
            mutated(peer_call, early.replace("pins_path=PINS)", "pins_path=PINS, additional_arguments=held)") + peer_call),
            "sel4-io-tcp",
        )

        # A repeated device counts each time. Two NICs in a site are refused until both the site table and the arm
        # table say two, and the record then lists two. One table updated and the other not is refused.
        net_pair = '"-device", f"virtio-net-device,netdev=slimenet,mac={mac}",'
        two_nics = mutated(net_pair, net_pair + " " + net_pair)
        copy.write_text(two_nics, encoding="utf-8")
        both = ("virtio-net-device", "virtio-net-device")
        sites_table = generator.QEMU_SITES[NETWORK_CHECKER]
        with patch.dict(generator.QEMU_SITES, {NETWORK_CHECKER: {**sites_table, "run_net_arm": both}}):
            refuse("two NICs with the arm table still saying one", lambda: generator.extract(copy, "sel4-net"))
            with patch.dict(generator.ARM_DEVICES, {NETWORK_CHECKER: {**declared, "sel4-net": both}}):
                if generator.extract(copy, "sel4-net")["devices"] != list(both):
                    fail("arm control: two declared NICs were not recorded as two devices")
                refused += 1
                if generator.render("sel4-net", "0" * 64, "qemu-arm-virt", generator.extract(copy, "sel4-net")).count('name = "virtio-net-device";') != 2:
                    fail("arm control: a record for two NICs does not list two devices")
                refused += 1
        with patch.dict(generator.ARM_DEVICES, {NETWORK_CHECKER: {**declared, "sel4-net": both}}):
            refuse("two NICs with the site table still saying one", lambda: generator.extract(copy, "sel4-net"))
        with patch.dict(generator.ARM_DEVICES, {NETWORK_CHECKER: {**declared, "sel4-net": both}}):
            copy.write_text(source, encoding="utf-8")
            refuse("an arm table that says two NICs for one", lambda: generator.extract(copy, "sel4-net"))
        copy.write_text(source, encoding="utf-8")

        plane = "def run_authority_arm(image: Path) -> None:\n"
        for label, text in (
            ("run_plane reached through an alias", mutated(plane, plane + "    go = run_plane\n")),
            ("run_plane reached as a module attribute", mutated(plane, plane + "    sel4_plane.run_plane(None)\n")),
            ("run_plane called with a spread mapping", mutated("        pins_path=PINS,\n    )\n    match_marker_contract(transcript, AUTHORITY_CHAINS", "        pins_path=PINS,\n        **extra,\n    )\n    match_marker_contract(transcript, AUTHORITY_CHAINS")),
            ("the keyword name held in a string", mutated(plane, plane + '    key = "additional_arguments"\n')),
            ("a second run_plane call that passes a device", mutated(plane, plane + '    run_plane(image=image, timeout=1, terminal_condition=None, fail=fail, additional_arguments=("-device", "virtio-rng-device"))\n')),
        ):
            refused_edit(label, text, "sel4-io-network")

        # An arm that runs inline in main() reaches no site of its own, so a branch of main() that can run such an
        # arm and reads a site is refused. The branches are read from the comparisons on the arm choice, and a
        # comparison that cannot be read as a branch is refused, so no branch can hide behind a constant or an alias.
        lifetime = '    if arguments.arm in ("lifetime", "all"):\n'
        refused_edit(
            "a device passed in main() for an inline arm",
            mutated(lifetime, lifetime + '        launch = ("-device", "virtio-net-device")\n'),
            "sel4-io-lifetime",
        )
        for call in ("run_net_arm(None, '', None)", "run_with_peer(None, '', None, None, ())", "run_zenoh_external_arm(None)", "run_http_request(None, '')"):
            refused_edit(f"the lifetime branch of main() calls {call.split('(')[0]}", mutated(lifetime, lifetime + f"        {call}\n"), "sel4-io-lifetime")
        refused_edit("the lifetime branch reads a site as a value", mutated(lifetime, lifetime + "        held = [run_net_arm]\n"), "sel4-io-lifetime")
        site_call = '        run_net_arm(None, "", None)\n'
        for label, text in (
            ("a second lifetime branch tested through a constant", mutated(lifetime, '    if arguments.arm == LIFETIME_CHOICE:\n' + site_call + lifetime).replace("TIMEOUT = 240\n", 'TIMEOUT = 240\nLIFETIME_CHOICE = "lifetime"\n', 1)),
            ("a second lifetime branch tested through a local alias", mutated(lifetime, '    which = arguments.arm\n    if which == "lifetime":\n' + site_call + lifetime)),
            ("a second lifetime branch with a computed name", mutated(lifetime, '    if arguments.arm in {"life" + "time"}:\n' + site_call + lifetime)),
            ("a second lifetime branch with the operands swapped", mutated(lifetime, '    if "lifetime" == arguments.arm:\n' + site_call + lifetime)),
            ("a branch that runs for every arm but one", mutated(lifetime, '    if arguments.arm != "net":\n' + site_call + lifetime)),
            ("a branch joined to another arm by or", mutated(lifetime, '    if arguments.arm == "lifetime" or arguments.arm == "net":\n' + site_call + lifetime)),
            ("an else of a branch that reads a site", mutated(lifetime, '    if arguments.arm == "net":\n        pass\n    else:\n' + site_call + lifetime)),
            ("a site read outside every arm branch", mutated(lifetime, site_call.removeprefix("    ") + lifetime)),
            ("the arm choice in a conditional expression", mutated(lifetime, '    held = 1 if arguments.arm == "lifetime" else 2\n' + lifetime)),
            ("the arm choice in a while loop", mutated(lifetime, '    while arguments.arm == "lifetime":\n        break\n' + lifetime)),
            ("the arm choice passed to a function", mutated(lifetime, '    print(arguments.arm)\n' + lifetime)),
            ("the arguments object aliased", mutated(lifetime, '    held = arguments\n' + lifetime)),
            ("the arm choice read by getattr", mutated(lifetime, '    if getattr(arguments, "arm") == "lifetime":\n' + site_call + lifetime)),
        ):
            refused_edit(label, text, "sel4-io-lifetime")
        copy.write_text(mutated(lifetime, '    if arguments.arm == "net2":\n' + site_call + lifetime), encoding="utf-8")
        if generator.extract(copy, "sel4-io-lifetime")["devices"] != []:
            fail("arm control: a branch that names only another arm changed the lifetime record")
        refused += 1
        refused_edit("the local branch of main() calls a site", mutated('    if arguments.arm in ("local", "all"):\n', '    if arguments.arm in ("local", "all"):\n        run_net_arm(None, "", None)\n'), "sel4-io-local")
        refused_edit(
            "the service-fault branch of main() calls a site",
            mutated('    if arguments.arm in ("service-fault", "all"):\n', '    if arguments.arm in ("service-fault", "all"):\n        run_net_arm(None, "", None)\n'),
            "sel4-io-service-fault-in-flight",
        )
        refused_edit(
            "the branch of an inline arm removed from main()",
            mutated(lifetime, '    if arguments.arm in ("renamed", "all"):\n'),
            "sel4-io-lifetime",
        )
        copy.write_text(source, encoding="utf-8")
        with patch.dict(generator.ARM_CHOICES, {NETWORK_CHECKER: {key: value for key, value in generator.ARM_CHOICES[NETWORK_CHECKER].items() if key != "sel4-io-local"}}):
            refuse("an inline arm with no entry in ARM_CHOICES", lambda: generator.extract(copy, "sel4-io-local"))

        # The entry table must name functions the checker defines, and every arm needs an entry.
        entries = generator.ARM_ENTRY_FUNCTIONS[NETWORK_CHECKER]
        for label, replacement in (
            ("an arm with no entry", {key: value for key, value in entries.items() if key != "sel4-http"}),
            ("an entry function the checker lacks", {**entries, "sel4-http": ("run_nothing_arm",)}),
        ):
            with patch.dict(generator.ARM_ENTRY_FUNCTIONS, {NETWORK_CHECKER: replacement}):
                refuse(label, lambda: generator.extract(copy, "sel4-http"))

        # Every closure the checker builds must be a declared run, whatever way the call is written.
        main_call = 'run_http_arm(build_image("sel4-http"), arguments.transcript, arguments.http_case)'
        for label, addition in (
            ("a build_image call with a keyword closure", '\n        build_image(closure="sel4-new")'),
            ("a build_image alias", '\n        boot = build_image\n        boot("sel4-new")'),
            ("a build_image call with a starred argument", '\n        build_image(*["sel4-new"])'),
            ("a build_image call with a computed closure", '\n        name = "sel4-new"\n        build_image(name)'),
            ("build_image passed as a value", "\n        held = [build_image]"),
        ):
            copy.write_text(mutated(main_call, main_call + addition), encoding="utf-8")
            refuse(label, lambda: built_closures(copy))
        copy.write_text(mutated(main_call, main_call + '\n        build_image("sel4-new")'), encoding="utf-8")
        if "sel4-new" not in built_closures(copy):
            fail("arm control: a positional build_image call for a new closure was not counted")
        refused += 1

        # Each arm must build exactly its own closure, so two call sites that swap their closures keep the set of
        # names the same and are still refused. A second closure, a foreign closure and no closure are refused too.
        authority_build = "image = build_image(CLOSURE) if not arguments.no_build else IMAGE"
        tcp_build = "image = build_image(TCP_CLOSURE)"
        swapped = (
            mutated(authority_build, "image = build_image(@A@) if not arguments.no_build else IMAGE")
            .replace(tcp_build, "image = build_image(@T@)")
            .replace("build_image(@A@)", "build_image(TCP_CLOSURE)")
            .replace("build_image(@T@)", "build_image(CLOSURE)")
        )
        if swapped.count("build_image(CLOSURE)") != 1 or swapped.count("build_image(TCP_CLOSURE)") != 1 or swapped == source:
            fail("arm control: the swap of the two closures was not built")
        for arm in ("sel4-io-network", "sel4-io-tcp"):
            refused_edit(f"CLOSURE and TCP_CLOSURE swapped, read for {arm}", swapped, arm)
        refused_edit("an arm that builds a second closure", mutated("        image = build_image(TCP_CLOSURE)\n", "        image = build_image(TCP_CLOSURE)\n        build_image(NET_CLOSURE)\n"), "sel4-io-tcp")
        refused_edit("an arm that builds a closure that is not its own", mutated("run_impairment_arm(build_image(IMPAIRMENT_CLOSURE)", "run_impairment_arm(build_image(LISTENER_CLOSURE)"), "sel4-io-tcp-impairment")
        refused_edit("an arm whose branch builds no closure", mutated('        image = build_image("sel4-io-lifetime")\n', "        image = None\n"), "sel4-io-lifetime")

        # A site read in the branch of an arm that has an entry function counts for that arm, and a site read in
        # the branch of another arm does not. The branch is found by the arm choice and not by the entry list.
        authority = '    if arguments.arm in ("authority", "all"):\n'
        refused_edit("a site called in the authority branch of main()", mutated(authority, authority + '        run_net_arm(None, "", None)\n'), "sel4-io-network")
        copy.write_text(mutated('    if arguments.arm == "net":\n', '    if arguments.arm == "net":\n        held = run_zenoh_external_arm\n'), encoding="utf-8")
        refused_edit("a second site read in the net branch of main()", copy.read_text(encoding="utf-8"), "sel4-net")

        # A name that an arm reaches must not be rebound. A local assignment, a parameter, a global declaration, a
        # second definition, an import, a decorator and a lookup by text would each send a call somewhere that the
        # reach did not look, so each is refused.
        tcp_head = "def run_tcp_arm(image: Path, mac: str, transcript_path: Path | None, *, driver_reset: bool = False) -> None:\n"
        refused_edit(
            "a local that rebinds a site to a function with no device",
            mutated(tcp_head, tcp_head + "    run_with_peer = run_without_device\n") + "\n\ndef run_without_device(*a, **k):\n    return run_plane(image=None, timeout=1, terminal_condition=None, fail=fail)\n",
            "sel4-io-tcp",
        )
        refused_edit("a parameter that hides a site", mutated(tcp_head, tcp_head.replace("driver_reset: bool = False", "driver_reset: bool = False, run_with_peer=None")), "sel4-io-tcp")
        refused_edit("a global declaration of a site", mutated(tcp_head, tcp_head + "    global run_with_peer\n    run_with_peer = None\n"), "sel4-io-tcp")
        refused_edit("a for loop that binds a site name", mutated(tcp_head, tcp_head + "    for run_with_peer in ():\n        pass\n"), "sel4-io-tcp")
        refused_edit("a with statement that binds a site name", mutated(tcp_head, tcp_head + "    with open('x') as run_with_peer:\n        pass\n"), "sel4-io-tcp")
        refused_edit("an import under a site name", mutated(tcp_head, tcp_head + "    import os as run_with_peer\n"), "sel4-io-tcp")
        refused_edit("a second top-level definition of a site", source + "\n\ndef run_with_peer(*a, **k):\n    return None\n", "sel4-io-tcp")
        refused_edit("a nested definition of a site name", mutated(tcp_head, tcp_head + "    def run_with_peer(*a, **k):\n        return None\n"), "sel4-io-tcp")
        refused_edit("a decorator on a site", mutated("def run_with_peer(", "@staticmethod\ndef run_with_peer("), "sel4-io-tcp")
        refused_edit("a function an arm reaches rebound as an entry", mutated(tcp_head, tcp_head + "    check_tcp_ledger = print\n"), "sel4-io-tcp")
        refused_edit("a lookup of a function by text with globals", mutated(tcp_head, tcp_head + "    globals()['run_with_peer']\n"), "sel4-io-tcp")
        refused_edit("a lookup of a function by text with getattr", mutated(tcp_head, tcp_head + "    getattr(sys.modules[__name__], 'run_with_peer')\n"), "sel4-io-tcp")
        refused_edit("an eval in the checker", mutated(tcp_head, tcp_head + "    eval('1')\n"), "sel4-io-tcp")
        refused_edit("a dunder attribute", mutated(tcp_head, tcp_head + "    run_tcp_arm.__globals__\n"), "sel4-io-tcp")
        refused_edit("the name of a site held in a string", mutated(tcp_head, tcp_head + "    held = 'run_with_peer'\n"), "sel4-io-tcp")
        refused_edit("run_plane imported a second time", mutated(tcp_head, tcp_head + "    from sel4_plane import run_plane\n"), "sel4-io-tcp")

        # The constants and modules that supply a closure to build_image are bound once at the top level, so a local
        # of the same name cannot change what a call builds. Each is refused whether it sits in main(), in an arm
        # function or in a parameter list, and an attribute of an imported module may not be stored.
        authority_branch = '    if arguments.arm in ("authority", "all"):\n'
        authority_fn = "def run_authority_arm(image: Path) -> None:\n"
        other = '"sel4-channel-fixture"'
        for label, text, arm in (
            ("CLOSURE assigned in main() before the call", mutated(authority_branch, f"    CLOSURE = {other}\n" + authority_branch), "sel4-io-network"),
            ("CLOSURE assigned inside the authority branch", mutated(authority_branch, authority_branch + f"        CLOSURE = {other}\n"), "sel4-io-network"),
            ("TCP_CLOSURE assigned in an arm function", mutated(tcp_head, tcp_head + f"    TCP_CLOSURE = {other}\n"), "sel4-io-tcp"),
            ("a parameter named CLOSURE", mutated(authority_fn, authority_fn.replace("image: Path", "image: Path, CLOSURE=None")), "sel4-io-network"),
            ("CLOSURE declared global in an arm function", mutated(authority_fn, authority_fn + "    global CLOSURE\n"), "sel4-io-network"),
            ("CLOSURE bound by a for loop", mutated(authority_fn, authority_fn + "    for CLOSURE in ():\n        pass\n"), "sel4-io-network"),
            ("CLOSURE bound by a walrus", mutated(authority_fn, authority_fn + "    (CLOSURE := 1)\n"), "sel4-io-network"),
            ("CLOSURE assigned a second time at the top level", source + f"\n\nCLOSURE = {other}\n", "sel4-io-network"),
            ("zenoh_capture rebound below the top level", mutated(tcp_head, tcp_head + "    import os as zenoh_capture\n"), "sel4-zenoh-external"),
            ("zenoh_capture.CLOSURE stored", mutated(authority_fn, authority_fn + f"    zenoh_capture.CLOSURE = {other}\n"), "sel4-zenoh-external"),
        ):
            refused_edit(label, text, arm)

        # Every route to build_image that is not a direct call by name is refused: an attribute of any object, a
        # subscript, a call of a call and a lookup through the module table.
        for label, addition in (
            ("build_image called through sys.modules", f'    sys.modules[__name__].build_image({other})\n'),
            ("build_image called as an attribute of a module", f'    checker.build_image({other})\n'),
            ("a callee that is a subscript", f'    table["x"]({other})\n'),
            ("a callee that is a call", f'    pick()({other})\n'),
            ("a callee that is a conditional expression", f'    (build_image if flag else print)({other})\n'),
        ):
            refused_edit(label, mutated(authority_fn, authority_fn + addition), "sel4-io-network")

        # The launcher is imported once, by name and without an alias, and its module is not imported as a whole.
        # A call through another name for it would launch QEMU without the keyword that the reading of a site needs.
        plane_import = "from sel4_plane import run_plane  # noqa: E402\n"
        early_launch = "        if peer is not None:\n            return launch(image=image, timeout=TIMEOUT, terminal_condition=terminal, fail=fail, pins_path=PINS)\n"
        peer_launch = "        transcript = run_plane(\n            image=image,\n            timeout=TIMEOUT,\n            terminal_condition=terminal,\n            fail=fail,\n            pins_path=PINS,\n            additional_arguments=("
        aliased = mutated(plane_import, plane_import + "from sel4_plane import run_plane as launch  # noqa: E402\n").replace(peer_launch, early_launch + peer_launch, 1)
        for label, text in (
            ("run_plane imported under another name and called without the keyword", aliased),
            ("run_plane imported under another name and not used", mutated(plane_import, plane_import + "from sel4_plane import run_plane as launch  # noqa: E402\n")),
            ("sel4_plane imported as a module", mutated(plane_import, plane_import + "import sel4_plane as plane  # noqa: E402\n")),
            ("something else imported from sel4_plane", mutated(plane_import, plane_import + "from sel4_plane import qemu_base_command  # noqa: E402\n")),
            ("a star import", mutated(plane_import, plane_import + "from sel4_plane import *  # noqa: E402\n")),
            ("run_plane imported from another module", mutated(plane_import, "from shim import run_plane  # noqa: E402\n")),
            ("run_plane imported from a submodule of sel4_plane", mutated(plane_import, "from sel4_plane.sub import run_plane  # noqa: E402\n")),
            ("run_plane imported by a relative import", mutated(plane_import, "from . import run_plane  # noqa: E402\n")),
        ):
            refused_edit(label, text, "sel4-io-tcp")

        # The fault words are read from what an arm runs in main() as well as from the functions it reaches. A word
        # in a branch for another arm, or in a function that no arm runs, does not count for this arm.
        tcp_branch = '    if arguments.arm in ("tcp", "all"):\n'
        for label, text, arm, expected in (
            ("a fault word in the main() branch of its own arm", mutated(tcp_branch, tcp_branch + "        device_fault = 1\n"), "sel4-io-tcp", ["device"]),
            ("a fault word in a main() statement outside the branches", mutated(authority_branch, '    print("DEVICE_FAULT")\n' + authority_branch), "sel4-io-tcp", ["device"]),
            ("a fault word on a later line of a statement outside the branches", mutated(authority_branch, '    print(\n        "DEVICE_FAULT"\n    )\n' + authority_branch), "sel4-io-tcp", ["device"]),
            ("a fault word in the main() branch of another arm", mutated(tcp_branch, '    if arguments.arm == "net2":\n        device_fault = 1\n' + tcp_branch), "sel4-io-tcp", []),
            ("a fault word in a function that no arm runs", source + "\n\ndef helper_unused():\n    device_fault = 1\n", "sel4-io-tcp", []),
            ("a fault word in a function the arm runs", mutated(tcp_head, tcp_head + "    note = 'DEVICE_FAULT'\n"), "sel4-io-tcp", ["device"]),
            ("a fault word in a branch that is not exact", mutated(tcp_branch, '    if arguments.arm != "net":\n        device_fault = 1\n' + tcp_branch), "sel4-io-tcp", ["device"]),
        ):
            copy.write_text(text, encoding="utf-8")
            if generator.extract(copy, arm)["faults"] != expected:
                fail(f"arm control: {label} gave faults {generator.extract(copy, arm)['faults']}, not {expected}")
            refused += 1
        copy.write_text(source, encoding="utf-8")

        # An arm's declared entry functions must be read by the branch of main() for its choice. Without that, a
        # branch could call a function with a different device and the declaration would still hold.
        net_call = "run_net_arm(build_image(NET_CLOSURE), mac, arguments.transcript)"
        options_call = "run_options_arm(build_image(OPTIONS_CLOSURE), mac, limits, arguments.transcript)"
        for label, text, arm in (
            ("the net branch calls the authority entry instead of its own", mutated(net_call, "run_authority_arm(build_image(NET_CLOSURE))"), "sel4-net"),
            ("the net branch drops the call to its entry", mutated(net_call, "build_image(NET_CLOSURE)"), "sel4-net"),
            ("the options branch drops the call to its entry", mutated(options_call, "build_image(OPTIONS_CLOSURE)"), "sel4-io-tcp-options"),
            ("the buffers branch calls the options entry instead of its own", mutated("run_buffers_arm(build_image(BUFFERS_CLOSURE)", "run_options_arm(build_image(BUFFERS_CLOSURE)"), "sel4-io-tcp-buffers"),
        ):
            refused_edit(label, text, arm)

        # An arm whose closure has not landed is planned. Its registration stays in PLANNED_RUNS until the closure
        # and the record exist. Without it the arm is a run with a missing closure, and its tables are still read.
        # No arm of this checker is planned today, so the controls name an absent closure for one arm that has
        # landed, or register that arm as planned.
        buffers = "sel4-io-tcp-buffers"
        if buffers in generator.PLANNED_RUNS:
            fail(f"arm control: {buffers} is planned again; these controls assume its closure has landed")
        declared_variants = generator.declared_variants

        def with_absent_closure(path):
            return [(name, f"{closure}-absent" if name == buffers else closure, profile, image)
                    for name, closure, profile, image in declared_variants(path)]

        with patch.object(generator, "declared_variants", with_absent_closure):
            refuse("an arm with an absent closure and no planning registration", lambda: generator.run_variants(checker))
        with patch.dict(generator.ARM_DEVICES, {NETWORK_CHECKER: {**declared, buffers: ()}}):
            refuse("an arm that declares no device but attaches one", lambda: generator.extract(checker, buffers))
        with patch.dict(generator.ARM_CHOICES, {NETWORK_CHECKER: {**generator.ARM_CHOICES[NETWORK_CHECKER], buffers: "tcp"}}):
            refuse("an arm read from the branch of another arm", lambda: generator.extract(checker, buffers))
        buffers_call = "run_buffers_arm(build_image(BUFFERS_CLOSURE)"
        refused_edit("an arm that builds the closure of another arm", mutated(buffers_call, "run_buffers_arm(build_image(TCP_CLOSURE)"), buffers)
        unfinished = sorted(item["id"] for item in generator.work_items.items() if item["state"] in {"open", "active", "blocked", "deferred"})
        if not unfinished:
            fail("arm control: no unfinished work item to register a planned arm under")
        stale = {**generator.PLANNED_RUNS, buffers: (unfinished[0], NETWORK_CHECKER, buffers, ("scripts/check/check-system-test-run.py",))}
        with patch.dict(generator.PLANNED_RUNS, stale, clear=True):
            refuse("a planning registration whose artifact already exists", lambda: generator.run_variants(checker))

        # A run record for a declared arm cannot go missing.
        runs = _Path(directory) / "runs"
        runs.mkdir()
        for record in RUN_ROOT.glob("*.zti"):
            (runs / record.name).write_bytes(record.read_bytes())
        (runs / "sel4-http.zti").unlink()
        with patch.dict(globals(), {"RUN_ROOT": runs}):
            refuse("a declared arm with no run record", check_records_and_planes_correspond)
    return refused


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory-controls", action="store_true",
                        help="exercise run inventory and arm isolation without a product boot")
    arguments = parser.parse_args()
    if arguments.inventory_controls:
        controls = check_inventory_controls() + check_arm_controls()
        print(f"system test run inventory controls: {controls} negative cases refused")
        return
    vocabulary = contract_vocabulary()
    record_count = check_records_and_planes_correspond()
    resolved, exempt, fault_count = check_records(vocabulary)
    check_records_match_their_checkers()
    control_count = check_controls(vocabulary) + check_declaration_controls()

    print(
        f"system test run check: {record_count} record(s) correspond one-to-one with the plane "
        f"gates that boot a seL4 image, each decoded through the contract with closed execution "
        f"and fault vocabularies and a bounded timeout; {resolved} name a closure that resolves to "
        f"their own plane and {exempt} name none because their image is declared closure-exempt; "
        f"{fault_count} fault control(s) declared; every record matches the checker it was frozen "
        f"from; and {control_count} named control(s) refused"
    )


if __name__ == "__main__":
    main()
