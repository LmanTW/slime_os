"""Unit tests of `scripts/build/build-data-volume.py`, run by `just frame_store_tools_check`."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import data_volume_contract as contract  # noqa: E402  (generated from contracts/data-volume/v1)

_SPEC = importlib.util.spec_from_file_location("build_data_volume", ROOT / "scripts" / "build" / "build-data-volume.py")
builder = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(builder)

FIXTURE = ROOT / "components" / "lib" / "src" / "frame_store" / "fixture.bin"


class Build(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def refused(self, kind: str, payload: Path, output: Path) -> str | None:
        try:
            builder.build(kind, payload, output)
        except builder.Refused as refusal:
            return refusal.args[0]
        return None

    def test_two_builds_are_identical_and_carry_the_contract_header(self) -> None:
        first, second = self.root / "a.img", self.root / "b.img"
        self.assertIsNone(self.refused("frame-store", FIXTURE, first))
        self.assertIsNone(self.refused("frame-store", FIXTURE, second))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        payload = FIXTURE.read_bytes()
        start = contract.FIRST_LBA * contract.SECTOR_BYTES
        header = first.read_bytes()[start:start + contract.VOLUME_HEADER_BYTES]
        self.assertEqual(
            contract.VOLUME_HEADER.unpack(header),
            (contract.VOLUME_MAGIC, contract.FORMAT_VERSION, contract.KIND_FRAME_STORE, len(payload),
             hashlib.sha256(payload).digest()),
        )

    def test_an_existing_output_is_left_alone(self) -> None:
        existing = self.root / "existing.img"
        existing.write_bytes(b"keep")
        self.assertEqual(self.refused("frame-store", FIXTURE, existing), "output")
        self.assertEqual(existing.read_bytes(), b"keep")

    def test_a_dangling_symlink_is_an_existing_output(self) -> None:
        link = self.root / "link.img"
        link.symlink_to(self.root / "missing")
        self.assertEqual(self.refused("frame-store", FIXTURE, link), "output")
        self.assertTrue(link.is_symlink())
        self.assertFalse((self.root / "missing").exists())

    def test_an_unknown_kind_and_a_non_store_are_refused_and_write_nothing(self) -> None:
        bad = self.root / "bad.bin"
        bad.write_bytes(b"\xff" + FIXTURE.read_bytes()[1:])
        self.assertEqual(self.refused("bitmap", FIXTURE, self.root / "kind.img"), "kind")
        self.assertEqual(self.refused("frame-store", bad, self.root / "store.img"), "payload")
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["bad.bin"])


if __name__ == "__main__":
    unittest.main()
