#!/usr/bin/env python3

"""Render the rmw_zenoh data exam's captured batches as the Rust constants the `zenoh_rmw_data::` tests read.

The captured bytes live in `scripts/lib/zenoh_rmw_data_peer.py`, which the rmw-data exam
(`check-zenoh-profile0.py --slice rmw-data`) also pins. This script writes them as one record of
`contracts/zenoh-rmw-data/v1`, lets that contract's `gen_rust.zt` decode and render it, and
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
import zenoh_rmw_data_exam

GENERATOR = ROOT / "contracts" / "zenoh-rmw-data" / "v1" / "gen_rust.zt"
RUST_OUTPUT = ROOT / "components" / "lib" / "src" / "zenoh_rmw_data" / "fixtures.rs"
INVALID = "INVALID_ZENOH_RMW_DATA_FIXTURES"


def render(source: str | None = None) -> str:
    with tempfile.TemporaryDirectory(prefix="slime-zenoh-rmw-data-bindings-") as temporary:
        staging = Path(temporary)
        record = staging / "fixtures.zti"
        record.write_text(zenoh_rmw_data_exam.fixture_zti() if source is None else source, encoding="utf-8")
        staged = staging / "components" / "lib" / "src" / "zenoh_rmw_data" / "fixtures.rs"
        staged.parent.mkdir(parents=True)
        environment = os.environ.copy()
        environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
        environment["SLIME_ZENOH_RMW_DATA_BINDINGS_ROOT"] = str(staging)
        environment["SLIME_ZENOH_RMW_DATA_FIXTURES_PATH"] = str(record)
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
            raise SystemExit("zenoh-rmw-data generator did not write bindings")
        rust = staged.read_text(encoding="utf-8")
        if INVALID in rust:
            raise SystemExit("zenoh-rmw-data record is refused by its contract")
        return rust


def corrupted_records(honest: str) -> list[tuple[str, str]]:
    """Records the contract's constants forbid, each of which the generator must refuse."""
    name, hexed = zenoh_rmw_data_exam.peer.PEERPUB[0]
    row = f'    {{ name = "{name}"; bytes = "{hexed}"; }};\n'
    extra = '    { name = "extra"; bytes = "00"; };\n'
    return [
        ("a 65th peerpub batch", honest.replace("  peerpub = [\n", "  peerpub = [\n" + extra, 1)),
        ("a peerpub batch missing", honest.replace(row, "", 1)),
        ("a 42nd slimepub batch", honest.replace("  slimepub = [\n", "  slimepub = [\n" + extra, 1)),
        ("a batch of 513 bytes", honest.replace(row, row.replace(hexed, "00" * 513), 1)),
        ("a batch that is not hexadecimal", honest.replace(row, row.replace(hexed, "zz"), 1)),
        ("a batch in upper case", honest.replace(row, row.replace(hexed, "AB"), 1)),
        ("a name with a quote", honest.replace(row, row.replace(name, name + '\\"'), 1)),
        ("formatVersion 2", honest.replace("formatVersion = 1;", "formatVersion = 2;")),
        ("an unknown field", honest.replace("formatVersion = 1;", "formatVersion = 1;\n  surprise = 1;", 1)),
    ]


def controls() -> None:
    honest = zenoh_rmw_data_exam.fixture_zti()
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
    print(f"Zenoh rmw data fixture controls: {len(records)} corrupted records refused")


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
            raise SystemExit("generated zenoh_rmw_data/fixtures.rs is stale; run `just zenoh_rmw_data_gen`")
        print("Zenoh rmw data fixtures are current")
        return
    write_atomic(RUST_OUTPUT, generated)
    print(f"Generated {RUST_OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
