"""The expectation `just data_volume_check` holds a data volume to.

`contracts/data-volume/v1/schema.zt` is the format. This module is an independent encoder and decoder for it,
the disks the exam boots, and the judgement of what the guest probe prints. It shares no code with the
volume builder or the guest reader; it reuses the frame-store exam's independent frame-store encoder and
decoder, which the frame-store item already landed.
"""

from __future__ import annotations

import hashlib
import re
import struct
import uuid
import zlib
from collections.abc import Iterator
from dataclasses import dataclass

import frame_store_exam as frames

SCHEMA = "contracts/data-volume/v1/schema.zt"
BUILDER = "scripts/build/build-data-volume.py"
CLOSURE = "sel4-data-volume"
PROBE = "data-volume-probe"
BUILDER_REFUSALS = ("kind", "output", "payload")

SECTOR = 512
FIRST_LBA = 2048
ENTRY_COUNT = 128
ENTRY_BYTES = 128
ENTRY_SECTORS = ENTRY_COUNT * ENTRY_BYTES // SECTOR
MAX_PAYLOAD_BYTES = 134_217_728
VOLUME_MAGIC = int.from_bytes(b"SLDV", "little")
FORMAT_VERSION = 1
KIND_FRAME_STORE = 1
TYPE_GUID = "8f4c2a91-3b7e-4d6a-9c15-5e2f7a0b4d38"
PARTITION_NAME = "slime-data-volume"
DISK_DOMAIN = b"slime-data-volume-v1:disk:"
PARTITION_DOMAIN = b"slime-data-volume-v1:partition:"
REFUSAL_CLASSES = ("gpt", "partition", "header", "length", "padding", "hash", "frame-store")
HEAP_BOUND = 65536

CONSTANTS = {
    "formatVersion": FORMAT_VERSION, "volumeMagic": VOLUME_MAGIC, "kindFrameStore": KIND_FRAME_STORE,
    "sectorBytes": SECTOR, "firstLba": FIRST_LBA, "gptEntryCount": ENTRY_COUNT, "gptEntryBytes": ENTRY_BYTES,
    "maxPayloadBytes": MAX_PAYLOAD_BYTES,
}
TEXTS = {
    "partitionTypeGuid": TYPE_GUID, "partitionName": PARTITION_NAME,
    "diskGuidDomain": DISK_DOMAIN.decode(), "partitionGuidDomain": PARTITION_DOMAIN.decode(),
}
HEADER_LAYOUT = (("magic", 4, False), ("version", 2, False), ("kind", 2, False), ("payloadBytes", 8, False),
                 ("payloadSha256", 32, True))
VOLUME_HEADER = struct.Struct("<IHHQ32s")
GPT_HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
GPT_ENTRY = struct.Struct("<16s16sQQQ72s")


class Refused(Exception):
    """The decoder refuses a disk. `check` names the one check that failed; `kind` is its refusal class, the
    part of `check` before its first hyphen for every class but `frame-store`."""

    def __init__(self, check: str, detail: str):
        kind = "frame-store" if check == "frame-store" else check.split("-", 1)[0]
        super().__init__(f"{check}: {detail}")
        assert kind in REFUSAL_CLASSES, check
        self.kind = kind
        self.check = check


def schema_findings(text: str) -> list[str]:
    """Where the schema text differs from the contract this exam pins."""
    findings = []
    for name, value in CONSTANTS.items():
        found = re.findall(rf"^{name} :: Int = (\d+);", text, re.M)
        if found != [str(value)]:
            findings.append(f"{name} must be stated once as {value}, found {found}")
    for name, value in TEXTS.items():
        found = re.findall(rf'^{name} :: Text = "([^"]*)";', text, re.M)
        if found != [value]:
            findings.append(f"{name} must be stated once as {value!r}, found {found}")
    block = re.search(r"^refusalClasses :: List Text = \{(.*?)^\};", text, re.M | re.S)
    if block is None or tuple(re.findall(r'"([a-z-]+)";', block.group(1))) != REFUSAL_CLASSES:
        findings.append(f"refusalClasses must be {list(REFUSAL_CLASSES)} in that order")
    block = re.search(r"^volumeHeaderLayout :: List WireField = \{(.*?)^\};", text, re.M | re.S)
    rows = () if block is None else tuple(
        (name, int(width), array == "true") for name, width, array in re.findall(
            r'\{ name = "(\w+)"; width = (\d+); signed = false; byteArray = (true|false); \};', block.group(1)))
    if block is None or rows != HEADER_LAYOUT or block.group(1).count("{") != len(HEADER_LAYOUT):
        findings.append(f"volumeHeaderLayout must be {HEADER_LAYOUT}")
    return findings


# The format.

def guid(text_or_bytes: str | bytes) -> bytes:
    """A GUID in the GPT mixed-endian encoding, from its text or from 16 raw bytes read as big-endian."""
    value = uuid.UUID(text_or_bytes) if isinstance(text_or_bytes, str) else uuid.UUID(bytes=text_or_bytes)
    return value.bytes_le


def payload_sectors(size: int) -> int:
    return (size + SECTOR - 1) // SECTOR


def geometry(size: int) -> tuple[int, int]:
    """(total sectors, last usable LBA) of the disk for a payload of `size` bytes."""
    last_usable = FIRST_LBA + payload_sectors(size)
    return last_usable + 1 + ENTRY_SECTORS + 1, last_usable


def _protective_mbr(total: int) -> bytes:
    mbr = bytearray(SECTOR)
    mbr[446:462] = bytes((0x00, 0x00, 0x02, 0x00, 0xEE, 0xFF, 0xFF, 0xFF)) + struct.pack(
        "<II", 1, min(total - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def _gpt_header(own: int, alternate: int, entries_lba: int, last_usable: int, disk_guid: bytes,
                entries_crc: int) -> bytes:
    fields = [b"EFI PART", 0x00010000, 92, 0, 0, own, alternate, ENTRY_SECTORS + 2, last_usable, disk_guid,
              entries_lba, ENTRY_COUNT, ENTRY_BYTES, entries_crc]
    raw = GPT_HEADER.pack(*fields)
    fields[3] = zlib.crc32(raw)
    return GPT_HEADER.pack(*fields).ljust(SECTOR, b"\0")


def encode(payload: bytes, *, kind: int = KIND_FRAME_STORE) -> bytes:
    """The one disk image of `payload`."""
    digest = hashlib.sha256(payload).digest()
    total, last_usable = geometry(len(payload))
    disk_guid = guid(hashlib.sha256(DISK_DOMAIN + digest).digest()[:16])
    part_guid = guid(hashlib.sha256(PARTITION_DOMAIN + digest).digest()[:16])
    name = PARTITION_NAME.encode("utf-16-le").ljust(72, b"\0")
    entries = GPT_ENTRY.pack(guid(TYPE_GUID), part_guid, FIRST_LBA, last_usable, 0, name).ljust(
        ENTRY_COUNT * ENTRY_BYTES, b"\0")
    crc = zlib.crc32(entries)
    out = bytearray(total * SECTOR)
    out[0:SECTOR] = _protective_mbr(total)
    out[SECTOR:2 * SECTOR] = _gpt_header(1, total - 1, 2, last_usable, disk_guid, crc)
    out[2 * SECTOR:(2 + ENTRY_SECTORS) * SECTOR] = entries
    header = VOLUME_HEADER.pack(VOLUME_MAGIC, FORMAT_VERSION, kind, len(payload), digest)
    out[FIRST_LBA * SECTOR:FIRST_LBA * SECTOR + len(header)] = header
    start = (FIRST_LBA + 1) * SECTOR
    out[start:start + len(payload)] = payload
    backup_entries = total - 1 - ENTRY_SECTORS
    out[backup_entries * SECTOR:(total - 1) * SECTOR] = entries
    out[(total - 1) * SECTOR:] = _gpt_header(total - 1, 1, backup_entries, last_usable, disk_guid, crc)
    return bytes(out)


def _header(disk: bytes, lba: int, which: str) -> tuple:
    sector = disk[lba * SECTOR:(lba + 1) * SECTOR]
    fields = list(GPT_HEADER.unpack_from(sector))
    _require(fields[0] == b"EFI PART", f"gpt-{which}-signature", f"the {which} GPT header's signature")
    _require(fields[1] == 0x00010000, f"gpt-{which}-revision", f"the {which} GPT header's revision")
    _require(fields[2] == 92, f"gpt-{which}-header-size", f"the {which} GPT header's size")
    _require(fields[4] == 0, f"gpt-{which}-header-reserved", f"the {which} GPT header's reserved field")
    stored = fields[3]
    fields[3] = 0
    _require(zlib.crc32(GPT_HEADER.pack(*fields)) == stored, f"gpt-{which}-header-crc",
             f"the {which} GPT header fails its CRC32")
    _require(not any(sector[GPT_HEADER.size:]), f"gpt-{which}-header-trailing",
             f"the {which} GPT header has bytes after its 92")
    fields[3] = stored
    return tuple(fields)


def _require(held: bool, check: str, detail: str) -> None:
    if not held:
        raise Refused(check, detail)


def decode(disk: bytes) -> bytes:
    """Validate a disk in the contract's order and return its payload. Raises Refused naming the first check
    that fails; each check is its own statement, so each has a disk that fails it alone."""
    _require(len(disk) % SECTOR == 0 and len(disk) >= (FIRST_LBA + 2 + ENTRY_SECTORS + 1) * SECTOR,
             "gpt-size", f"{len(disk)} bytes is not a whole disk of the minimum size")
    total = len(disk) // SECTOR
    mbr = disk[:SECTOR]
    _require(mbr[510:512] == b"\x55\xaa", "gpt-mbr-signature", "the MBR signature")
    _require(mbr[450] == 0xEE, "gpt-mbr-type", "the MBR partition type is not 0xEE")
    _require(struct.unpack_from("<II", mbr, 454) == (1, min(total - 1, 0xFFFFFFFF)), "gpt-mbr-range",
             "the protective partition does not run from LBA 1 over the disk")
    primary = _header(disk, 1, "primary")
    backup = _header(disk, total - 1, "backup")
    _require(primary[5] == 1, "gpt-primary-own-lba", "the primary header does not name LBA 1")
    _require(primary[6] == total - 1, "gpt-primary-alternate-lba", "the primary header does not name the last LBA")
    _require(backup[5] == total - 1, "gpt-backup-own-lba", "the backup header does not name the last LBA")
    _require(backup[6] == 1, "gpt-backup-alternate-lba", "the backup header does not name LBA 1")
    _require(primary[10] == 2, "gpt-primary-entries-lba", "the primary entry array is not at LBA 2")
    _require(backup[10] == total - 1 - ENTRY_SECTORS, "gpt-backup-entries-lba",
             "the backup entry array is not before the backup header")
    for index, field in ((7, "first-usable"), (8, "last-usable"), (9, "disk-guid"), (11, "entry-count"),
                         (12, "entry-size"), (13, "entries-crc-field")):
        _require(primary[index] == backup[index], f"gpt-headers-differ-{field}", f"the two headers' {field} differ")
    _require(primary[11] == ENTRY_COUNT, "gpt-entry-count", f"the headers name {primary[11]} entries")
    _require(primary[12] == ENTRY_BYTES, "gpt-entry-size", f"the headers name {primary[12]}-byte entries")
    _require(primary[7] == ENTRY_SECTORS + 2, "gpt-first-usable", f"the first usable LBA is {primary[7]}")
    _require(primary[8] < total - 1 - ENTRY_SECTORS, "gpt-last-usable", f"the last usable LBA is {primary[8]}")
    arrays = []
    for which, header in (("primary", primary), ("backup", backup)):
        start = header[10] * SECTOR
        array = disk[start:start + ENTRY_COUNT * ENTRY_BYTES]
        _require(zlib.crc32(array) == header[13], f"gpt-{which}-entries-crc", f"the {which} entry array's CRC32")
        arrays.append(array)
    type_guid, _, first, last, attributes, name = GPT_ENTRY.unpack_from(arrays[0])
    _require(type_guid == guid(TYPE_GUID), "partition-type", "entry 0 is not a data volume")
    _require(not any(arrays[0][ENTRY_BYTES:]), "partition-other-entry", "an entry after entry 0 is not zero")
    _require(first == FIRST_LBA, "partition-first-lba", f"the volume starts at {first}")
    _require(last == primary[8], "partition-last-lba", f"the volume ends at {last}, not the last usable LBA")
    _require(attributes == 0, "partition-attributes", "the volume's attributes are not zero")
    _require(name == PARTITION_NAME.encode("utf-16-le").ljust(72, b"\0"), "partition-name", "the volume's name")
    header = disk[FIRST_LBA * SECTOR:(FIRST_LBA + 1) * SECTOR]
    magic, version, kind, size, digest = VOLUME_HEADER.unpack_from(header)
    _require(magic == VOLUME_MAGIC, "header-magic", "the volume magic")
    _require(version == FORMAT_VERSION, "header-version", f"volume version {version}")
    _require(kind == KIND_FRAME_STORE, "header-kind", f"payload kind {kind}")
    _require(not any(header[VOLUME_HEADER.size:]), "header-reserved", "a reserved header byte is not zero")
    _require(size != 0, "length-zero", "the payload length is zero")
    _require(size <= MAX_PAYLOAD_BYTES, "length-bound", f"payload length {size} is above {MAX_PAYLOAD_BYTES}")
    _require(payload_sectors(size) == last - FIRST_LBA, "length-sectors",
             f"payload length {size} does not fill the partition's {last - FIRST_LBA} sectors")
    start = (FIRST_LBA + 1) * SECTOR
    payload = disk[start:start + size]
    _require(not any(disk[start + size:(last + 1) * SECTOR]), "padding", "a byte after the payload is not zero")
    _require(hashlib.sha256(payload).digest() == digest, "hash", "the payload's SHA-256 is not the header's")
    try:
        frames.decode(payload)
    except frames.Refused as error:
        raise Refused("frame-store", f"the payload is not a frame store: {error}") from error
    return payload


# The disks the exam boots.

def payload() -> bytes:
    """The honest payload: a frame store with a LiDAR-sized frame, an empty frame, and frames that straddle
    sector and 4 KiB request boundaries, its bytes a fixed pseudo-random stream."""
    def stream(seed: int, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            out += hashlib.sha256(b"slime-data-volume-exam:%d:%d" % (seed, counter)).digest()
            counter += 1
        return bytes(out[:length])
    sizes = (494_889, 4097, 1, 0, 70_001, 131_072, 513, 203)
    store = frames.Store(
        topic="/exam/velodyne_points", type_name=frames.BAG_TYPE, type_hash=frames.HASH, schema="uint8 x\n",
        period_ns=frames.BAG_PERIOD_NS,
        frames=tuple((1_790_000_000_000_000_000 + index * frames.BAG_PERIOD_NS, stream(index, size))
                     for index, size in enumerate(sizes)),
    )
    return frames.encode(store)


def _sector(disk: bytes, lba: int, change) -> bytes:
    data = bytearray(disk)
    sector = bytearray(data[lba * SECTOR:(lba + 1) * SECTOR])
    change(sector)
    data[lba * SECTOR:(lba + 1) * SECTOR] = sector
    return bytes(data)


def _gpt(disk: bytes, which: str, index: int, value, *, fix_crc: bool = True) -> bytes:
    """The same disk with header field `index` set to `value` in the `primary`, `backup` or `both` headers,
    each edited header's CRC32 recomputed unless `fix_crc` is false."""
    total = len(disk) // SECTOR
    data = bytearray(disk)
    lbas = {"primary": (1,), "backup": (total - 1,), "both": (1, total - 1)}[which]
    for lba in lbas:
        fields = list(GPT_HEADER.unpack_from(data, lba * SECTOR))
        fields[index] = value(fields[index]) if callable(value) else value
        if fix_crc and index != 3:
            fields[3] = 0
            fields[3] = zlib.crc32(GPT_HEADER.pack(*fields))
        data[lba * SECTOR:lba * SECTOR + GPT_HEADER.size] = GPT_HEADER.pack(*fields)
    return bytes(data)


def _entries(disk: bytes, offset: int, value: bytes, *, which: str = "both", fix_crc: bool = True) -> bytes:
    """The same disk with `value` written at `offset` of the `primary`, `backup` or `both` entry arrays, the
    arrays' CRC32 fields (and the headers' CRC32s) recomputed unless `fix_crc` is false."""
    total = len(disk) // SECTOR
    data = bytearray(disk)
    pairs = {"primary": ((1, 2),), "backup": ((total - 1, total - 1 - ENTRY_SECTORS),)}
    pairs["both"] = pairs["primary"] + pairs["backup"]
    for header_lba, entries_lba in pairs[which]:
        base = entries_lba * SECTOR
        data[base + offset:base + offset + len(value)] = value
        if not fix_crc:
            continue
        fields = list(GPT_HEADER.unpack_from(data, header_lba * SECTOR))
        fields[13] = zlib.crc32(bytes(data[base:base + ENTRY_COUNT * ENTRY_BYTES]))
        fields[3] = 0
        fields[3] = zlib.crc32(GPT_HEADER.pack(*fields))
        data[header_lba * SECTOR:header_lba * SECTOR + GPT_HEADER.size] = GPT_HEADER.pack(*fields)
    return bytes(data)


def not_a_store(store: bytes) -> bytes:
    """`store` with its magic broken: a payload whose header hash matches but the frame-store reader refuses."""
    broken = bytearray(store)
    broken[0] ^= 0xFF
    return bytes(broken)


def corrupted(honest: bytes, store: bytes) -> dict[str, bytes]:
    """One disk per check of the decoder, keyed by the check it is built to fail first and alone. A semantic
    edit recomputes every CRC32 it disturbs, so only the named check can refuse it."""
    start = (FIRST_LBA + 1) * SECTOR
    size = len(store)
    total = len(honest) // SECTOR
    last_usable = FIRST_LBA + payload_sectors(size)

    def at(lba: int, offset: int, value: bytes) -> bytes:
        data = bytearray(honest)
        data[lba * SECTOR + offset:lba * SECTOR + offset + len(value)] = value
        return bytes(data)

    def volume(offset: int, value: bytes) -> bytes:
        return at(FIRST_LBA, offset, value)

    def entry(offset: int, value: bytes) -> bytes:
        return _entries(honest, offset, value)

    disks = {
        # Below the minimum size, which a guest sees in the device capacity. A disk that is not a whole number
        # of sectors cannot be booted as one: the block device rounds it, so that half of the check stays
        # this decoder's input check.
        "gpt-size": honest[:(FIRST_LBA + 2 + ENTRY_SECTORS) * SECTOR],
        "gpt-mbr-signature": at(0, 510, b"\x00"),
        "gpt-mbr-type": at(0, 450, b"\x83"),
        "gpt-mbr-range": at(0, 454, struct.pack("<I", 2)),
        "gpt-primary-signature": _gpt(honest, "primary", 0, b"EFI PARU"),
        "gpt-primary-revision": _gpt(honest, "primary", 1, 0x00010001),
        "gpt-primary-header-size": _gpt(honest, "primary", 2, 96),
        "gpt-primary-header-reserved": _gpt(honest, "primary", 4, 1),
        "gpt-primary-header-crc": _gpt(honest, "primary", 3, lambda crc: crc ^ 1),
        "gpt-primary-header-trailing": at(1, 200, b"\x01"),
        "gpt-backup-signature": _gpt(honest, "backup", 0, b"EFI PARU"),
        "gpt-backup-revision": _gpt(honest, "backup", 1, 0x00010001),
        "gpt-backup-header-size": _gpt(honest, "backup", 2, 96),
        "gpt-backup-header-reserved": _gpt(honest, "backup", 4, 1),
        "gpt-backup-header-crc": _gpt(honest, "backup", 3, lambda crc: crc ^ 1),
        "gpt-backup-header-trailing": at(total - 1, 200, b"\x01"),
        "gpt-primary-own-lba": _gpt(honest, "primary", 5, 5),
        "gpt-primary-alternate-lba": _gpt(honest, "primary", 6, total - 2),
        "gpt-backup-own-lba": _gpt(honest, "backup", 5, total - 2),
        "gpt-backup-alternate-lba": _gpt(honest, "backup", 6, 2),
        "gpt-primary-entries-lba": _gpt(honest, "primary", 10, 3),
        "gpt-backup-entries-lba": _gpt(honest, "backup", 10, total - 2 - ENTRY_SECTORS),
        "gpt-headers-differ-first-usable": _gpt(honest, "primary", 7, ENTRY_SECTORS + 3),
        "gpt-headers-differ-last-usable": _gpt(honest, "primary", 8, last_usable - 1),
        "gpt-headers-differ-disk-guid": _gpt(honest, "primary", 9, lambda value: bytes([value[0] ^ 1]) + value[1:]),
        "gpt-headers-differ-entry-count": _gpt(honest, "primary", 11, ENTRY_COUNT - 1),
        "gpt-headers-differ-entry-size": _gpt(honest, "primary", 12, ENTRY_BYTES * 2),
        "gpt-headers-differ-entries-crc-field": _gpt(honest, "primary", 13, lambda crc: crc ^ 1),
        "gpt-entry-count": _gpt(honest, "both", 11, ENTRY_COUNT - 1),
        "gpt-entry-size": _gpt(honest, "both", 12, ENTRY_BYTES * 2),
        "gpt-first-usable": _gpt(honest, "both", 7, 0),
        "gpt-last-usable": _gpt(honest, "both", 8, total - 1 - ENTRY_SECTORS),
        "gpt-primary-entries-crc": _entries(honest, ENTRY_BYTES + 3, b"\x01", fix_crc=False),
        "gpt-backup-entries-crc": _entries(honest, ENTRY_BYTES + 3, b"\x01", which="backup", fix_crc=False),
        "partition-type": entry(0, guid("0fc63daf-8483-4772-8e79-3d69d8477de4")),
        "partition-other-entry": entry(ENTRY_BYTES + 3, b"\x01"),
        "partition-first-lba": entry(32, struct.pack("<Q", FIRST_LBA - 1)),
        "partition-last-lba": entry(40, struct.pack("<Q", last_usable - 1)),
        "partition-attributes": entry(48, struct.pack("<Q", 1)),
        "partition-name": entry(56, "S".encode("utf-16-le")),
        "header-magic": volume(0, struct.pack("<I", VOLUME_MAGIC ^ 1)),
        "header-version": volume(4, struct.pack("<H", FORMAT_VERSION + 1)),
        "header-kind": volume(6, struct.pack("<H", KIND_FRAME_STORE + 1)),
        "header-reserved": volume(100, b"\x01"),
        "length-zero": volume(8, struct.pack("<Q", 0)),
        "length-bound": volume(8, struct.pack("<Q", MAX_PAYLOAD_BYTES + 1)),
        "length-sectors": volume(8, struct.pack("<Q", size + SECTOR)),
        "padding": at(0, start + size, b"\x01"),
        "hash": at(0, start + 7, bytes([honest[start + 7] ^ 0x01])),
        "frame-store": encode(not_a_store(store)),
    }
    return disks


def check_class(check: str) -> str:
    return "frame-store" if check == "frame-store" else check.split("-", 1)[0]


# What the probe prints.

TAG = f"[{PROBE}] "
VOLUME_LINE = re.compile(r"volume kind=frame-store bytes=(\d+) sha256=([0-9a-f]{64})")
FRAMES_LINE = re.compile(r"frames count=(\d+) period=(\d+) first=(\d+) last=(\d+) digest=([0-9a-f]{64})")
HEAP_LINE = re.compile(r"heap used=(\d+)")


def probe_lines(transcript: str) -> list[str]:
    return [line.split(TAG, 1)[1].strip() for line in transcript.splitlines() if TAG in line]


def volume_line(payload: bytes) -> str:
    return f"volume kind=frame-store bytes={len(payload)} sha256={hashlib.sha256(payload).hexdigest()}"


def expected_volume(store: bytes) -> tuple[str, str]:
    reading = frames.decode(store)
    payloads = b"".join(store[frame.offset:frame.offset + frame.length] for frame in reading.frames)
    return (
        volume_line(store),
        f"frames count={len(reading.frames)} period={reading.period_ns} first={reading.frames[0].log_time} "
        f"last={reading.frames[-1].log_time} digest={hashlib.sha256(payloads).hexdigest()}",
    )


def honest_findings(lines: list[str], store: bytes) -> list[str]:
    volume, frame_line = expected_volume(store)
    if len(lines) != 5:
        return [f"the probe printed {lines}, not the five lines of an accepted volume"]
    findings = []
    for got, want in ((lines[0], volume), (lines[1], frame_line), (lines[2], "write refused"),
                      (lines[4], "complete")):
        if got != want:
            findings.append(f"the probe printed {got!r}, not {want!r}")
    heap = HEAP_LINE.fullmatch(lines[3])
    if heap is None or int(heap.group(1)) > HEAP_BOUND:
        findings.append(f"the probe's heap line {lines[3]!r} is not at most {HEAP_BOUND} bytes")
    return findings


def refusal_findings(lines: list[str], kind: str, store: bytes) -> list[str]:
    wanted = ([volume_line(not_a_store(store))] if kind == "frame-store" else []) + [f"refused {kind}"]
    return [] if lines == wanted else [f"the probe printed {lines}, not {wanted}"]


DRIVER_TAG = "[virtio-blk-driver] "
DRIVER_AUTHORITY = "authority rings=1 rights=read source=generation"
DRIVER_REFUSAL = "refused write ring=0 rights=read"


def driver_findings(transcript: str) -> list[str]:
    """The block driver, which enforces the ring's rights, must report the read-only authority it read and
    the one write it refused, before the probe reports the refusal."""
    authority = refused = probe_refusal = None
    for index, line in enumerate(transcript.splitlines()):
        if DRIVER_TAG in line:
            text = line.split(DRIVER_TAG, 1)[1].strip()
            if text.startswith("authority ") and authority is None:
                authority = (index, text)
            if text.startswith("refused "):
                refused = (index, text) if refused is None else (-1, "more than one refusal")
        elif TAG in line and line.split(TAG, 1)[1].strip() == "write refused":
            probe_refusal = index
    findings = []
    if authority is None or authority[1] != DRIVER_AUTHORITY:
        findings.append(f"the driver reported authority {authority and authority[1]!r}, not {DRIVER_AUTHORITY!r}")
    if refused is None or refused[1] != DRIVER_REFUSAL:
        findings.append(f"the driver reported {refused and refused[1]!r}, not one {DRIVER_REFUSAL!r}")
    elif probe_refusal is None or refused[0] > probe_refusal:
        findings.append("the driver's refusal does not precede the probe's")
    if authority is not None and (probe_refusal is None or authority[0] > probe_refusal):
        findings.append("the driver's authority report does not precede the probe's refusal")
    return findings


BUILDER_REFUSAL = re.compile(r"build-data-volume: refused ([a-z-]+)")


def builder_refusal(stderr: str) -> str | None:
    lines = [line for line in stderr.splitlines() if line.strip()]
    match = BUILDER_REFUSAL.fullmatch(lines[-1].strip()) if lines else None
    return match.group(1) if match else None


# Controls.

@dataclass(frozen=True)
class Corpus:
    store: bytes
    honest: bytes
    broken: dict[str, bytes]


def corpus() -> Corpus:
    store = payload()
    honest = encode(store)
    return Corpus(store, honest, corrupted(honest, store))


def _verdict(disk: bytes) -> str:
    try:
        decode(disk)
    except Refused as refusal:
        return refusal.kind
    return "accepted"


def _check(disk: bytes) -> str:
    try:
        decode(disk)
    except Refused as refusal:
        return refusal.check
    return "accepted"


def _decoder_controls(data: Corpus) -> Iterator[tuple[str, bool]]:
    yield "decode-honest", _verdict(data.honest) == "accepted" and decode(data.honest) == data.store
    for check, disk in data.broken.items():
        yield f"decode-{check}", _check(disk) == check
    yield "decode-every-class-covered", {check_class(check) for check in data.broken} == set(REFUSAL_CLASSES)
    small = frames.encode(frames.BASE)
    yield "decode-small-store", decode(encode(small)) == small
    yield "decode-truncated-disk", _verdict(data.honest[:-SECTOR]) == "gpt"
    yield "decode-partial-sector", _check(data.honest[:-1]) == "gpt-size"
    yield "decode-backup-header", _verdict(_sector(data.honest, len(data.honest) // SECTOR - 1,
                                                   lambda s: s.__setitem__(24, s[24] ^ 1))) == "gpt"
    yield "decode-mbr", _verdict(_sector(data.honest, 0, lambda s: s.__setitem__(450, 0x83))) == "gpt"
    yield "decode-header-reserved", _verdict(_sector(data.honest, FIRST_LBA, lambda s: s.__setitem__(100, 1))) == "header"
    yield "decode-zero-length", _verdict(_sector(data.honest, FIRST_LBA, lambda s: s.__setitem__(
        slice(8, 16), struct.pack("<Q", 0)))) == "length"
    yield "decode-short-length", _verdict(_sector(data.honest, FIRST_LBA, lambda s: s.__setitem__(
        slice(8, 16), struct.pack("<Q", len(data.store) - SECTOR)))) == "length"
    yield "decode-kind", _verdict(encode(data.store, kind=2)) == "header"
    yield "encode-deterministic", encode(data.store) == data.honest
    other = bytearray(data.store)
    other[-1] ^= 1
    yield "encode-guid-follows-payload", encode(bytes(other))[SECTOR + 56:SECTOR + 72] != data.honest[SECTOR + 56:SECTOR + 72]


def _transcript_controls(data: Corpus) -> Iterator[tuple[str, bool]]:
    volume, frame_line = expected_volume(data.store)
    honest = [volume, frame_line, "write refused", "heap used=4096", "complete"]
    yield "probe-honest", not honest_findings(honest, data.store)
    cases = {
        "probe-missing-complete": honest[:4],
        "probe-extra-line": [*honest, "complete"],
        "probe-wrong-bytes": [volume.replace(f"bytes={len(data.store)}", f"bytes={len(data.store) + 1}"), *honest[1:]],
        "probe-wrong-sha": [volume[:-1] + ("0" if volume[-1] != "0" else "1"), *honest[1:]],
        "probe-wrong-digest": [volume, frame_line[:-1] + ("0" if frame_line[-1] != "0" else "1"), *honest[2:]],
        "probe-wrong-count": [volume, frame_line.replace("count=8", "count=7"), *honest[2:]],
        "probe-no-write-refusal": [volume, frame_line, "write accepted", *honest[3:]],
        "probe-heap-over": [volume, frame_line, "write refused", f"heap used={HEAP_BOUND + 1}", "complete"],
        "probe-reordered": [frame_line, volume, *honest[2:]],
    }
    for label, lines in cases.items():
        yield label, bool(honest_findings(lines, data.store))
    for kind in REFUSAL_CLASSES:
        good = [volume_line(not_a_store(data.store)), "refused frame-store"] if kind == "frame-store" else [f"refused {kind}"]
        yield f"probe-refusal-{kind}", not refusal_findings(good, kind, data.store)
        other = REFUSAL_CLASSES[(REFUSAL_CLASSES.index(kind) + 1) % len(REFUSAL_CLASSES)]
        yield f"probe-refusal-{kind}-wrong-class", bool(refusal_findings([f"refused {other}"], kind, data.store))
        yield f"probe-refusal-{kind}-then-complete", bool(refusal_findings([*good, "complete"], kind, data.store))
    yield "probe-refusal-hash-after-volume", bool(refusal_findings([volume, "refused hash"], "hash", data.store))
    yield "probe-refusal-frame-store-honest-volume", bool(refusal_findings([volume, "refused frame-store"], "frame-store", data.store))
    good = (f"{DRIVER_TAG}{DRIVER_AUTHORITY}\n{DRIVER_TAG}{DRIVER_REFUSAL}\n{TAG}write refused\n")
    yield "driver-honest", not driver_findings(good)
    for label, text in {
        "driver-read-write": good.replace("rights=read source", "rights=read,write source"),
        "driver-no-refusal": good.replace(f"{DRIVER_TAG}{DRIVER_REFUSAL}\n", ""),
        "driver-two-refusals": good.replace(f"{TAG}write", f"{DRIVER_TAG}{DRIVER_REFUSAL}\n{TAG}write"),
        "driver-after-probe": f"{DRIVER_TAG}{DRIVER_AUTHORITY}\n{TAG}write refused\n{DRIVER_TAG}{DRIVER_REFUSAL}\n",
        "driver-probe-only": f"{TAG}write refused\n",
        "driver-other-ring": good.replace("ring=0 rights=read\n", "ring=1 rights=read\n"),
        "driver-authority-after-probe": f"{DRIVER_TAG}{DRIVER_REFUSAL}\n{TAG}write refused\n{DRIVER_TAG}{DRIVER_AUTHORITY}\n",
    }.items():
        yield label, bool(driver_findings(text))
    yield "builder-refusal-honest", builder_refusal("x\nbuild-data-volume: refused payload\n") == "payload"
    yield "builder-refusal-not-last", builder_refusal("build-data-volume: refused payload\ndone\n") is None
    yield "builder-refusal-other-tool", builder_refusal("convert-mcap: refused payload\n") is None


def controls() -> list[tuple[str, bool]]:
    """Each control and whether it held."""
    data = corpus()
    return [*_decoder_controls(data), *_transcript_controls(data)]
