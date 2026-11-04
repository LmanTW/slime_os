#!/usr/bin/env python3

"""Judge the generation builder's Zenoh limits record, and the system spec admission that runs it.

`just zenoh_service_limits_builder_check` runs this script. The judge is `scripts/lib/zenoh_limits_builder_exam.py`: it
builds the record from a manifest and from a spec, requires the encoder's bytes and the independent struct writer's bytes,
holds the rows to the holders, subscriptions and key length the record declares, and refuses each input the contract and the
manifest forbid.

The exam is imported here, at the top of the file, so `devloop-approval` follows it into this recipe's closure, and with it
the system spec modules it imports. The limits slice lives in `check-zenoh-profile0.py`, which does not import the exam, so
a change to the system spec does not stale its evidence.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

from typing import NoReturn

import devloop_observations
import zenoh_limits_builder_exam

CASES = 11
CONTROLS = 15


def fail(message: str) -> NoReturn:
    raise SystemExit(f"zenoh profile 0 check failed: {message}")


def main() -> int:
    """Honest checks that the builder emits the right bytes, and refusals. The exam exits through `SystemExit` at the
    first thing that does not hold, so a run that returns has passed every check."""
    try:
        positive, refusals = zenoh_limits_builder_exam.controls()
    except SystemExit as error:
        fail(str(error))
    if positive != CASES:
        fail(f"limits-builder: {positive} checks passed, the checker pins {CASES}")
    if refusals != CONTROLS:
        fail(f"limits-builder: {refusals} refusals, the checker pins {CONTROLS}")
    print(f"[zenoh-profile0] slice=limits-builder cases={positive} refusals={refusals} controls={refusals}")
    devloop_observations.record(casesObserved=positive, negativeControlsRefused=refusals)
    print("zenoh profile 0 limits-builder check: the builder emits the encoder's bytes and holds the rows to the declared limits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
