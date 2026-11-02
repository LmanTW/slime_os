# Data volume format 1

A data volume carries one hash-pinned payload on a disk that a QEMU run attaches read-only. `schema.zt` is
the normative layout and refusal order. Version 1 admits one payload kind, a
[`frame-store/v1`](../../frame-store/v1/README.md) store.

## Why a disk

A recording is a run input, not an image input. No system-image closure names the disk, so a new recording
changes no derivation id and needs no new image. The run that attaches the disk pins its SHA-256, and the
disk's GUIDs derive from the payload's SHA-256, so one payload has exactly one disk image.

## Layout

| Sectors | Content |
| --- | --- |
| 0 | protective MBR |
| 1 | primary GPT header |
| 2–33 | primary partition entry array; entry 0 is the volume |
| 34–2047 | zero |
| 2048 | volume header: magic `SLDV`, version, kind, payload length, payload SHA-256 |
| 2049– | payload, then zero to the end of its last sector |
| next 32 | backup partition entry array |
| last | backup GPT header |

The partition type GUID is `8F4C2A91-3B7E-4D6A-9C15-5E2F7A0B4D38` (written here in upper case; the schema states it in lower case). Its name is `slime-data-volume`.

## Refusal order

| Order | Class | The reader refuses when |
| --- | --- | --- |
| 1 | `gpt` | the protective MBR, a GPT header or an entry array is invalid, or the two copies disagree |
| 2 | `partition` | entry 0 is not a data volume, another entry is not zero, or the range is not the layout's |
| 3 | `header` | the volume header's magic, version, kind or a reserved byte is wrong |
| 4 | `length` | the payload length is zero, too large, or not the partition's |
| 5 | `padding` | a byte after the payload in its last sector is not zero |
| 6 | `hash` | the payload's SHA-256 is not the header's |
| 7 | `frame-store` | the frame-store reader refuses the payload |

## Writer and reader

`scripts/build/build-data-volume.py --kind frame-store --payload FILE --output DISK` writes a disk. A
components/lib reader validates one through a block ring, in the order above, without holding the
payload whole. The testkit component `data-volume-probe` in the `sel4-data-volume` composition reports
what it read. `just data_volume_check` judges both. Work item `01a19add-bddf-77a3-ab9c-ca12ecb6512f` implements them; until then the
check fails.
