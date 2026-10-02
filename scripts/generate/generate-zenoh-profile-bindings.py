#!/usr/bin/env python3

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

GENERATOR = ROOT / "contracts" / "zenoh-profile" / "v1" / "schema.zt"
RUST_OUTPUT = ROOT / "components" / "proto" / "src" / "zenoh_profile.rs"
INVALID_SCHEMA = "INVALID_ZENOH_PROFILE_SCHEMA"


def render() -> str:
    with tempfile.TemporaryDirectory(prefix="slime-zenoh-profile-bindings-") as temporary:
        staging = Path(temporary)
        staged_rust = staging / "components" / "proto" / "src" / "zenoh_profile.rs"
        staged_rust.parent.mkdir(parents=True)
        environment = os.environ.copy()
        environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
        environment["SLIME_ZENOH_PROFILE_BINDINGS_ROOT"] = str(staging)
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
        if not staged_rust.exists():
            raise SystemExit("zenoh-profile generator did not write bindings")
        rust = staged_rust.read_text(encoding="utf-8")
        if INVALID_SCHEMA in rust:
            raise SystemExit("zenoh-profile schema validation failed")
        return rust


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
    arguments = parser.parse_args()
    generated = format_rust(render())
    if arguments.check:
        if not RUST_OUTPUT.exists() or RUST_OUTPUT.read_text(encoding="utf-8") != generated:
            raise SystemExit(
                "generated zenoh_profile.rs is stale; run `just zenoh_profile_gen`"
            )
        print("Zenoh profile bindings are current")
        return
    write_atomic(RUST_OUTPUT, generated)
    print(f"Generated {RUST_OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
