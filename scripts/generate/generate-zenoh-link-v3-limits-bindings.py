#!/usr/bin/env python3

"""Render the constants of `contracts/zenoh-link-limits/v3` as the Rust file a link configuration reads.

The constants live in `contracts/zenoh-link-limits/v3/schema.zt`. The link-limits v3 exam
(`check-zenoh-profile0.py --slice link-limits-v3`) renders the same text with `zenoh_link_v3_limits_exam.render_bindings`
and requires the committed `components/proto/src/zenoh_link_v3_limits.rs` to equal it byte for byte, so
this script and the exam cannot disagree about a constant. Run `just zenoh_link_v3_limits_gen` to write the
file and `--check` to compare it without writing.
"""

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
from pathlib import Path

from harness import ROOT
import zenoh_link_v3_limits_exam


def write_atomic(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(contents.encode("utf-8"))
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    try:
        rendered = zenoh_link_v3_limits_exam.render_bindings()
    except zenoh_link_v3_limits_exam.LinkV3Error as error:
        raise SystemExit(str(error)) from error
    output = zenoh_link_v3_limits_exam.GENERATED
    if arguments.check:
        if not output.exists() or output.read_bytes() != rendered.encode("utf-8"):
            raise SystemExit(f"generated {output.relative_to(ROOT)} is stale; run `just zenoh_link_v3_limits_gen`")
        print("Zenoh link limits v3 constants are current")
        return
    write_atomic(output, rendered)
    print(f"Generated {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
