#!/usr/bin/env python3

"""Write a `contracts/data-volume/v1` disk: the one GPT disk image of a frame-store payload.

    build-data-volume.py --kind frame-store --payload FILE --output DISK

The payload must be a valid `contracts/frame-store/v1` store. The disk's GUIDs derive from the payload's
SHA-256, so a payload has exactly one image and two builds of it are identical. The disk is written to a
temporary file beside DISK and renamed into place, so a refused or interrupted build leaves nothing.

A refusal exits nonzero and ends stderr with `build-data-volume: refused CLASS`:

    kind      the kind is not `frame-store`
    output    DISK already exists
    payload   the payload cannot be read, is empty or above the contract's bound, or is not a frame store
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "tools" / "frame-store"))

import argparse
import hashlib
import os
import struct
import sys
import uuid
import zlib
from pathlib import Path

import data_volume_contract as contract
import frame_store

SECTOR = contract.SECTOR_BYTES
ENTRY_ARRAY_BYTES = contract.GPT_ENTRY_COUNT * contract.GPT_ENTRY_BYTES
ENTRY_SECTORS = ENTRY_ARRAY_BYTES // SECTOR
GPT_HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
GPT_ENTRY = struct.Struct("<16s16sQQQ72s")
KINDS = {"frame-store": contract.KIND_FRAME_STORE}


class Refused(Exception):
    """A refusal: `args[0]` is its class, `args[1]` the reason."""


def _guid(raw: bytes) -> bytes:
    """Sixteen bytes read as a big-endian GUID, in the GPT mixed-endian encoding."""
    return uuid.UUID(bytes=raw).bytes_le


def _gpt_header(own: int, alternate: int, entries_lba: int, last_usable: int, disk_guid: bytes, entries_crc: int) -> bytes:
    fields = [b"EFI PART", 0x00010000, GPT_HEADER.size, 0, 0, own, alternate, ENTRY_SECTORS + 2, last_usable,
              disk_guid, entries_lba, contract.GPT_ENTRY_COUNT, contract.GPT_ENTRY_BYTES, entries_crc]
    fields[3] = zlib.crc32(GPT_HEADER.pack(*fields))
    return GPT_HEADER.pack(*fields).ljust(SECTOR, b"\0")


def disk_image(payload: bytes, kind: int) -> bytes:
    """The contract's one disk image of `payload`."""
    digest = hashlib.sha256(payload).digest()
    payload_sectors = (len(payload) + SECTOR - 1) // SECTOR
    last_usable = contract.FIRST_LBA + payload_sectors
    total = last_usable + 1 + ENTRY_SECTORS + 1
    disk_guid = _guid(hashlib.sha256(contract.DISK_GUID_DOMAIN.encode() + digest).digest()[:16])
    partition_guid = _guid(hashlib.sha256(contract.PARTITION_GUID_DOMAIN.encode() + digest).digest()[:16])
    name = contract.PARTITION_NAME.encode("utf-16-le").ljust(72, b"\0")
    entries = GPT_ENTRY.pack(uuid.UUID(contract.PARTITION_TYPE_GUID).bytes_le, partition_guid, contract.FIRST_LBA,
                             last_usable, 0, name).ljust(ENTRY_ARRAY_BYTES, b"\0")
    entries_crc = zlib.crc32(entries)
    image = bytearray(total * SECTOR)
    # The protective MBR: one partition of type 0xEE from LBA 1 over the disk.
    image[446:462] = bytes((0x00, 0x00, 0x02, 0x00, 0xEE, 0xFF, 0xFF, 0xFF)) + struct.pack(
        "<II", 1, min(total - 1, 0xFFFFFFFF))
    image[510:512] = b"\x55\xaa"
    image[SECTOR:2 * SECTOR] = _gpt_header(1, total - 1, 2, last_usable, disk_guid, entries_crc)
    image[2 * SECTOR:(2 + ENTRY_SECTORS) * SECTOR] = entries
    # The header's struct is rendered from the contract's `volumeHeaderLayout`; only the GPT structures,
    # which the UEFI specification owns, are spelled here.
    header = contract.VOLUME_HEADER.pack(contract.VOLUME_MAGIC, contract.FORMAT_VERSION, kind, len(payload), digest)
    image[contract.FIRST_LBA * SECTOR:contract.FIRST_LBA * SECTOR + len(header)] = header
    start = (contract.FIRST_LBA + 1) * SECTOR
    image[start:start + len(payload)] = payload
    backup_entries = total - 1 - ENTRY_SECTORS
    image[backup_entries * SECTOR:(total - 1) * SECTOR] = entries
    image[(total - 1) * SECTOR:] = _gpt_header(total - 1, 1, backup_entries, last_usable, disk_guid, entries_crc)
    return bytes(image)


def build(kind_name: str, payload_path: Path, output: Path) -> None:
    kind = KINDS.get(kind_name)
    if kind is None:
        raise Refused("kind", f"{kind_name!r} is not one of {sorted(KINDS)}")
    # `exists()` follows a symlink, so a dangling one would read as absent and be replaced.
    if output.is_symlink() or output.exists():
        raise Refused("output", f"{output} already exists")
    try:
        payload = payload_path.read_bytes()
    except OSError as error:
        raise Refused("payload", f"cannot read {payload_path}: {error}") from error
    if not 0 < len(payload) <= contract.MAX_PAYLOAD_BYTES:
        raise Refused("payload", f"{len(payload)} bytes is outside 1..{contract.MAX_PAYLOAD_BYTES}")
    try:
        frame_store.validate(payload)
    except frame_store.InvalidStore as error:
        raise Refused("payload", f"the payload is not a frame store: {error}") from error
    image = disk_image(payload, kind)
    staged = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        staged.write_bytes(image)
        os.replace(staged, output)
    finally:
        staged.unlink(missing_ok=True)
    print(f"build-data-volume: wrote {output} ({len(image)} bytes, payload sha256 "
          f"{hashlib.sha256(payload).hexdigest()})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--kind", required=True, help="the payload kind; version 1 admits frame-store")
    parser.add_argument("--payload", type=Path, required=True, help="the payload file")
    parser.add_argument("--output", type=Path, required=True, help="the disk image to write; must not exist")
    arguments = parser.parse_args()
    try:
        build(arguments.kind, arguments.payload, arguments.output)
    except Refused as refusal:
        sys.stderr.write(f"build-data-volume: {refusal.args[1]}\n")
        sys.stderr.write(f"build-data-volume: refused {refusal.args[0]}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
