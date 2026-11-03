#!/usr/bin/env python3

"""Judge the allowed additions to the frozen console transport sources.

`scripts/lib/console_record_controls.py` pins the exact bytes of `components/runtime/src/syscall/sel4_transport.rs` and
`components/runtime/src/syscall.rs`, and allows one named block in each: the Zenoh grants read. This script runs only
the controls of that exemption and records two counts. `casesObserved` is how many fixtures the pin accepted, and
`negativeControlsRefused` is how many it refused. Both are pinned by the exam, which rejects a run that makes any other
number, so a removed control fails the run and does not leave it green.

The counts are those of the exemption alone. The larger gate controls hold totals that move whenever any gate changes,
and binding them here would fail this item for changes that have nothing to do with it.

`just console_pin_additions_check` runs this script.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

from typing import NoReturn

import console_record_controls
import devloop_observations
from harness import ROOT


def fail(message: str) -> NoReturn:
    raise SystemExit(f"console pin additions check failed: {message}")


def main() -> int:
    try:
        accepted, refused = console_record_controls.addition_results(ROOT)
    except (OSError, ValueError) as error:
        fail(str(error))
    print(f"[console-pin-additions] accepted={accepted} refused={refused}")
    devloop_observations.record(casesObserved=accepted, negativeControlsRefused=refused)
    print("console pin additions check: the pins hold with each allowed block and without it, and refuse every other change")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
