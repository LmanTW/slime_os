#!/usr/bin/env python3

"""Render the rmw_zenoh graph exam's synthetic rows as the Rust constants the `zenoh_rmw_graph::` tests read.

The captured bytes live in `scripts/lib/zenoh_rmw_graph_exam.py`, which the rmw-graph exam
(`check-zenoh-profile0.py --slice rmw-graph`) also pins. This script writes them as one record of
`contracts/zenoh-rmw-graph/v1`, lets that contract's `gen_rust.zt` decode and render it, and
formats the result, so the tests and the exam cannot disagree about a byte.
"""

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from zutai_cli import STDLIB, binary

from harness import ROOT
import zenoh_rmw_graph_exam

GENERATOR = ROOT / "contracts" / "zenoh-rmw-graph" / "v1" / "gen_rust.zt"
RUST_OUTPUT = ROOT / "components" / "lib" / "src" / "zenoh_rmw_graph" / "fixtures.rs"
INVALID = "INVALID_ZENOH_RMW_GRAPH_FIXTURES"


def render(source: str | None = None) -> str:
    with tempfile.TemporaryDirectory(prefix="slime-zenoh-rmw-graph-bindings-") as temporary:
        staging = Path(temporary)
        record = staging / "fixtures.zti"
        record.write_text(zenoh_rmw_graph_exam.fixture_zti() if source is None else source, encoding="utf-8")
        staged = staging / "components" / "lib" / "src" / "zenoh_rmw_graph" / "fixtures.rs"
        staged.parent.mkdir(parents=True)
        environment = os.environ.copy()
        environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
        environment["SLIME_ZENOH_RMW_GRAPH_BINDINGS_ROOT"] = str(staging)
        environment["SLIME_ZENOH_RMW_GRAPH_FIXTURES_PATH"] = str(record)
        process = subprocess.run(
            [str(binary()), "run", str(GENERATOR)],
            cwd=ROOT,
            env=environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.returncode != 0:
            sys.stderr.write(process.stdout)
            sys.stderr.write(process.stderr)
            raise SystemExit(process.returncode)
        if not staged.exists():
            raise SystemExit("zenoh-rmw-graph generator did not write bindings")
        rust = staged.read_text(encoding="utf-8")
        if INVALID in rust:
            raise SystemExit("zenoh-rmw-graph record is refused by its contract")
        return rust


def corrupted_records(honest: str) -> list[tuple[str, str]]:
    """Records the contract's constants forbid, each of which the generator must refuse."""
    name, key = zenoh_rmw_graph_exam.QOS_ROWS[0]
    row = f'    {{ name = "{name}"; key = "{key}"; }};\n'
    extra = '    { name = "extra"; key = "x"; };\n'
    return [
        ("a 13th qos row", honest.replace("  qos = [\n", "  qos = [\n" + extra, 1)),
        ("a qos row missing", honest.replace(row, "", 1)),
        ("a 9th token row", honest.replace("  tokens = [\n", "  tokens = [\n" + extra, 1)),
        ("a 22nd refuse row", honest.replace("  refuse = [\n", "  refuse = [\n" + extra, 1)),
        ("a 5th qosRefuse row", honest.replace("  qosRefuse = [\n", "  qosRefuse = [\n" + extra, 1)),
        ("a 3rd ignored row", honest.replace("  ignored = [\n", "  ignored = [\n" + extra, 1)),
        ("a key of 254 bytes", honest.replace(row, row.replace(key, "k" * 254), 1)),
        ("a key with a quote", honest.replace(row, row.replace(key, key + '"'), 1)),
        ("a key with a backslash", honest.replace(row, row.replace(key, key + "\\"), 1)),
        ("formatVersion 2", honest.replace("formatVersion = 1;", "formatVersion = 2;")),
        ("a name over 64 bytes", honest.replace(f'name = "{name}"', 'name = "' + "n" * 65 + '"', 1)),
        ("an unknown field", honest.replace("formatVersion = 1;", "formatVersion = 1;\n  surprise = 1;", 1)),
    ]


def controls() -> None:
    honest = zenoh_rmw_graph_exam.fixture_zti()
    render(honest)
    records = corrupted_records(honest)
    for label, record in records:
        if record == honest:
            raise SystemExit(f"control '{label}' did not change the record")
        try:
            render(record)
        except SystemExit:
            continue
        raise SystemExit(f"generator rendered a record it must refuse: {label}")
    print(f"Zenoh rmw graph fixture controls: {len(records)} corrupted records refused")


def format_rust(source: str) -> str:
    process = subprocess.run(
        ["rustfmt", "--edition", "2024", "--emit", "stdout"],
        cwd=ROOT,
        input=source,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        sys.stderr.write(process.stderr)
        raise SystemExit(process.returncode)
    return process.stdout


def write_atomic(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(contents, encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--controls", action="store_true", help="prove the generator refuses corrupted records")
    arguments = parser.parse_args()
    if arguments.controls:
        controls()
        return
    generated = format_rust(render())
    if arguments.check:
        if not RUST_OUTPUT.exists() or RUST_OUTPUT.read_text(encoding="utf-8") != generated:
            raise SystemExit("generated zenoh_rmw_graph/fixtures.rs is stale; run `just zenoh_rmw_graph_gen`")
        print("Zenoh rmw graph fixtures are current")
        return
    write_atomic(RUST_OUTPUT, generated)
    print(f"Generated {RUST_OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
