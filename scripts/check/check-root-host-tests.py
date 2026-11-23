#!/usr/bin/env python3

"""Print the number of host tests that `just test_sel4_root` must run, and nothing else.

The count and its controls are `scripts/lib/root_host_tests.py`. The controls run first, so a counter that miscounts
the synthetic crate prints no number. The count is reported as `hostTests`, and the number of control cases as
`hostTestCountControls`.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import devloop_observations  # noqa: E402
import root_host_tests  # noqa: E402
import rust_source  # noqa: E402


def main() -> int:
    try:
        cases = root_host_tests.controls()
        expected = root_host_tests.count()
    except rust_source.SourceError as error:
        raise SystemExit(f"root host test count failed: {error}") from error
    devloop_observations.record(hostTests=expected, hostTestCountControls=cases)
    print(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
