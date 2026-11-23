#!/usr/bin/env python3

"""The generation builder writes the reader table its rule gives, and no other row.

`contracts/resource-reader/v1` pairs a generation table with an instance that may
read it. The root holds no component name for these tables: it serves a table to
an instance exactly when a row names that pair. The names are in the builder, so
this judge is what holds them:

    table                   payload                 reader
    entropy authority       entropy-authority       the instance named entropy-service
    Zenoh grants            zenoh-grants            the instance named zenoh-service
    Zenoh limits            zenoh-limits            the instance named zenoh-service
    network destinations    network-destinations    the instance named network-service
    network interfaces      network-interface       the instance named network-service
    network applications    network-application     the instance named network-service
    block ring authority    block-ring-authority    every instance of the executable virtio-blk-driver

The builder writes a row only for a table the generation carries and an instance
the manifest declares, and it writes no object when no row remains.

The product entry is `build_resource_readers(manifest, emitted)`, reached through
`scripts/build/build-generation.py`. `manifest["instances"]` holds the declared
instances, and `emitted` holds the payload ids the build carries. It returns the
object's bytes, or `None`.

The judge writes the expected bytes itself. It reads the layout, the resource
ids, the bounds and the identity domain from `schema.zt` through `zutai json`,
and it imports no binding the builder uses. For each manifest below the builder
must return those bytes, and it must refuse a table above the schema's row
bound.

The controls run first. Each is a builder with one defect: a row for another
instance, a row for every instance, a missing row, a block reader chosen by
instance name, a named reader chosen by executable, a row for a table the
generation does not carry, an empty object in place of none, rows out of order,
an identity without the domain tag, and a table above the bound. The judge must
refuse each one and accept its own writer.

The gate boots nothing and reads no composition. Whether the root honours the
table is the root's host tests and the booted planes.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import hashlib
import json
from collections.abc import Callable
from typing import NoReturn

import devloop_observations
import zutai_cli
from harness import ROOT, load_script

SCHEMA = ROOT / "contracts" / "resource-reader" / "v1" / "schema.zt"
ENTRY = "build_resource_readers"
# (resource id in the schema, payload id in the builder, instance field, value that field must hold).
RULE = (
    ("resourceEntropyAuthority", "entropy-authority", "name", "entropy-service"),
    ("resourceZenohGrants", "zenoh-grants", "name", "zenoh-service"),
    ("resourceZenohLimits", "zenoh-limits", "name", "zenoh-service"),
    ("resourceNetworkDestinations", "network-destinations", "name", "network-service"),
    ("resourceNetworkInterfaces", "network-interface", "name", "network-service"),
    ("resourceNetworkApplications", "network-application", "name", "network-service"),
    ("resourceBlockRingAuthority", "block-ring-authority", "executable", "virtio-blk-driver"),
)
PAYLOADS = frozenset(payload for _, payload, _, _ in RULE)
READERS = (
    {"name": "entropy-service", "executable": "entropy-service"},
    {"name": "zenoh-service", "executable": "zenoh-service"},
    {"name": "network-service", "executable": "network-service"},
    {"name": "disk-a", "executable": "virtio-blk-driver"},
    {"name": "disk-b", "executable": "virtio-blk-driver"},
)
BYSTANDERS = (
    {"name": "init", "executable": "init"},
    {"name": "shell", "executable": "slisp"},
)
# Instances that carry a reader's name in the other field. None of them reads.
IMPOSTORS = (
    {"name": "virtio-blk-driver", "executable": "init"},
    {"name": "entropy-copy", "executable": "entropy-service"},
    {"name": "zenoh-copy", "executable": "zenoh-service"},
    {"name": "network-copy", "executable": "network-service"},
)

Builder = Callable[[dict, set[str]], bytes | None]
Rows = list[tuple[int, bytes]]


class Refused(Exception):
    """The judge refuses a builder; the message names the manifest and the difference."""


def fail(message: str) -> NoReturn:
    raise SystemExit(f"resource reader builder check: {message}")


def schema_format() -> dict:
    try:
        raw = zutai_cli.evaluate("json", SCHEMA, input_path=SCHEMA, env_var="SLIME_UNUSED")
    except zutai_cli.ZutaiError as error:
        fail(f"{SCHEMA.relative_to(ROOT)} does not evaluate: {error}")
    value = json.loads(raw)["format"]
    for layout, size in (("headerLayout", "headerBytes"), ("entryLayout", "entryBytes")):
        if sum(field["width"] for field in value[layout]) != value[size]:
            fail(f"the schema's {layout} does not add up to {size}")
    return value


def record(layout: list[dict], values: dict[str, int | bytes]) -> bytes:
    """One record, written field by field from the schema's layout."""
    if set(values) != {field["name"] for field in layout}:
        fail(f"the judge's values {sorted(values)} do not match the schema's layout")
    out = b""
    for field in layout:
        value = values[field["name"]]
        if field["byteArray"]:
            if not isinstance(value, bytes) or len(value) != field["width"]:
                fail(f"the judge's value for {field['name']} is not {field['width']} bytes")
            out += value
        else:
            out += int(value).to_bytes(field["width"], "little", signed=field["signed"])
    return out


def identity(fmt: dict, name: str) -> bytes:
    encoded = name.encode("utf-8")
    return hashlib.sha256(fmt["identityDomain"].encode("ascii") + len(encoded).to_bytes(2, "little") + encoded).digest()


def rule_rows(fmt: dict, manifest: dict, emitted: set[str]) -> Rows:
    return sorted(
        (fmt[resource], identity(fmt, instance["name"]))
        for resource, payload, field, value in RULE
        if payload in emitted
        for instance in manifest["instances"]
        if instance.get(field) == value
    )


def table(fmt: dict, rows: Rows) -> bytes:
    header = record(
        fmt["headerLayout"],
        {
            "magic": fmt["magicTag"].encode("ascii") + b"\0",
            "format_version": fmt["formatVersion"],
            "header_size": fmt["headerBytes"],
            "required_flags": 0,
            "row_count": len(rows),
            "total_len": fmt["headerBytes"] + len(rows) * fmt["entryBytes"],
        },
    )
    return header + b"".join(record(fmt["entryLayout"], {"resource": resource, "reader_identity": reader}) for resource, reader in rows)


def reference(fmt: dict) -> Builder:
    """The judge's own writer of the rule. The controls are this writer with one defect."""

    def build(manifest: dict, emitted: set[str]) -> bytes | None:
        rows = rule_rows(fmt, manifest, emitted)
        if len(rows) > fmt["maxRows"]:
            raise SystemExit("resource readers exceed the row bound")
        return table(fmt, rows) if rows else None

    return build


def manifests(fmt: dict) -> list[tuple[str, dict, set[str], bool]]:
    """Each case as (label, manifest, emitted payloads, whether the builder must refuse it)."""
    everyone = [*READERS, *BYSTANDERS, *IMPOSTORS]
    cases = [
        ("every reader and every table", {"instances": everyone}, set(PAYLOADS), False),
        ("the instances in reverse order", {"instances": everyone[::-1]}, set(PAYLOADS), False),
        ("no table", {"instances": everyone}, set(), False),
        ("no reader", {"instances": [*BYSTANDERS, *IMPOSTORS]}, set(PAYLOADS), False),
        ("a payload the rule does not name", {"instances": everyone}, {"clock-authority"}, False),
    ]
    cases += [(f"without the table {payload}", {"instances": everyone}, set(PAYLOADS - {payload}), False) for payload in sorted(PAYLOADS)]
    cases += [(f"only the table {payload}", {"instances": everyone}, {payload}, False) for payload in sorted(PAYLOADS)]
    cases += [
        (f"without the instance {reader['name']}", {"instances": [i for i in everyone if i is not reader]}, set(PAYLOADS), False)
        for reader in READERS
    ]
    full = [{"name": f"disk-{index:02}", "executable": "virtio-blk-driver"} for index in range(fmt["maxRows"])]
    cases.append(("as many block drivers as the row bound", {"instances": full}, {"block-ring-authority"}, False))
    over = [*full, {"name": "disk-over", "executable": "virtio-blk-driver"}]
    cases.append(("one block driver above the row bound", {"instances": over}, {"block-ring-authority"}, True))
    return cases


def judge(fmt: dict, build: Builder) -> int:
    """Hold `build` to the rule on every manifest. Returns the number of cases; raises `Refused`."""
    seen = set()
    for label, manifest, emitted, refuse in manifests(fmt):
        try:
            got = build(manifest, set(emitted))
        except SystemExit as error:
            if not refuse:
                raise Refused(f"{label}: the builder refused a table within the bound: {error}") from error
            continue
        if refuse:
            raise Refused(f"{label}: the builder wrote a table above the bound of {fmt['maxRows']} rows")
        rows = rule_rows(fmt, manifest, emitted)
        want = table(fmt, rows) if rows else None
        if got != want:
            raise Refused(f"{label}: the builder's table is not the {len(rows)} row(s) of the rule")
        seen.add(want)
    # A judge whose cases all expect one table would pass a builder that ignores its input.
    if len(seen) < 10 or None not in seen:
        raise Refused(f"the cases expect only {len(seen)} distinct tables")
    return len(manifests(fmt))


def defects(fmt: dict) -> list[tuple[str, Builder]]:
    honest = reference(fmt)
    grants = fmt["resourceZenohGrants"]
    block = fmt["resourceBlockRingAuthority"]

    def rows_of(manifest: dict, emitted: set[str]) -> Rows:
        return rule_rows(fmt, manifest, emitted)

    def finish(rows: Rows) -> bytes | None:
        return table(fmt, sorted(set(rows))) if rows else None

    def another_instance(manifest, emitted):
        rows = rows_of(manifest, emitted)
        extra = [(grants, identity(fmt, "init"))] if any(resource == grants for resource, _ in rows) else []
        return finish(rows + extra)

    def every_instance(manifest, emitted):
        rows = rows_of(manifest, emitted)
        extra = [(grants, identity(fmt, i["name"])) for i in manifest["instances"]] if "zenoh-grants" in emitted else []
        return finish(rows + extra)

    def missing_row(manifest, emitted):
        rows = rows_of(manifest, emitted)
        drop = (block, identity(fmt, "disk-b"))
        return finish([row for row in rows if row != drop])

    def block_by_name(manifest, emitted):
        rows = [row for row in rows_of(manifest, emitted) if row[0] != block]
        if "block-ring-authority" in emitted:
            rows += [(block, identity(fmt, i["name"])) for i in manifest["instances"] if i["name"] == "virtio-blk-driver"]
        return finish(rows)

    def named_by_executable(manifest, emitted):
        rows = rows_of(manifest, emitted)
        extra = [(grants, identity(fmt, i["name"])) for i in manifest["instances"] if i.get("executable") == "zenoh-service"]
        return finish(rows + (extra if "zenoh-grants" in emitted else []))

    def absent_table(manifest, emitted):
        return honest(manifest, set(PAYLOADS) if emitted else set())

    def empty_object(manifest, emitted):
        return honest(manifest, emitted) or table(fmt, [])

    def unsorted(manifest, emitted):
        rows = rows_of(manifest, emitted)
        return table(fmt, rows[::-1]) if rows else None

    def bare_identity(manifest, emitted):
        rows = rows_of(manifest, emitted)
        names = {identity(fmt, i["name"]): hashlib.sha256(i["name"].encode("utf-8")).digest() for i in manifest["instances"]}
        return finish([(resource, names[reader]) for resource, reader in rows])

    def unbounded(manifest, emitted):
        return finish(rows_of(manifest, emitted))

    return [
        ("a row for another instance", another_instance),
        ("a row for every instance", every_instance),
        ("a missing row", missing_row),
        ("a block reader chosen by instance name", block_by_name),
        ("a named reader chosen by executable", named_by_executable),
        ("a row for a table the generation does not carry", absent_table),
        ("an empty object in place of none", empty_object),
        ("rows out of order", unsorted),
        ("an identity without the domain tag", bare_identity),
        ("a table above the row bound", unbounded),
    ]


def controls(fmt: dict) -> int:
    try:
        judge(fmt, reference(fmt))
    except Refused as error:
        fail(f"control: the judge refuses its own writer: {error}")
    refused = 0
    for label, build in defects(fmt):
        try:
            judge(fmt, build)
        except Refused:
            refused += 1
            continue
        fail(f"control: the judge accepts a builder with {label}")
    return refused


def main() -> int:
    if _sys.argv[1:] not in ([], ["--controls-only"]):
        fail(f"unknown arguments {_sys.argv[1:]}; the script takes --controls-only or nothing")
    fmt = schema_format()
    refused = controls(fmt)
    print(f"resource reader builder check: {refused} defective builders refused, and the judge's own writer accepted")
    if _sys.argv[1:]:
        return 0
    builder = load_script("resource_reader_check_builder", "build/build-generation.py")
    build = getattr(builder, ENTRY, None)
    if build is None:
        fail(f"scripts/build/build-generation.py has no {ENTRY}; the builder does not write the reader table yet")
    try:
        cases = judge(fmt, build)
    except Refused as error:
        fail(str(error))
    devloop_observations.record(readerTableCases=cases, negativeControlsRefused=refused)
    print(f"resource reader builder check: the builder writes the rule's table for {cases} manifests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
