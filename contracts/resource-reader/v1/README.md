# Resource readers, version 1

`schema.zt` defines the generation resource that names who reads each
generation table the root serves to a declared reader. `gen_rust.zt` renders
its Rust constants and its Python layout; `just boot_gen` writes both.
`boot-contracts/src/resource_reader.rs` owns decoding.
`scripts/build/generation_resources.py` owns encoding.

## Meaning

A row pairs one table with one instance. The root serves a table to an instance
only when a row names that pair. The root holds no component name for these
tables. A generation without the object has no reader of any of them.

| Id | Table | Reader the builder declares |
| --- | --- | --- |
| 1 | `entropy-authority/v1` | the instance named `entropy-service` |
| 2 | `zenoh-service-grants-table/v1` | the instance named `zenoh-service` |
| 3 | `zenoh-service-limits/v1` | the instance named `zenoh-service` |
| 4 | `network-destination/v1` | the instance named `network-service` |
| 5 | `network-interface/v1` | the instance named `network-service` |
| 6 | `network-application/v4` | the instance named `network-service` |
| 7 | `block-authority/v1` | every instance of the executable `virtio-blk-driver` |

The builder writes a row only for a table the generation carries and an
instance the manifest declares. The builder emits the object only when it has at
least one row. No manifest declares the object.

A row grants the read and nothing else. The root still filters block rows by the
device of the caller's `ioResourceBudget` row.

## Encoding

The 32-byte header contains magic `SLIMERR\0`, format version 1, header size,
zero required flags, row count, and exact total length. At most 64 rows follow.
Each row is 36 bytes:

| Field | Offset | Width | Meaning |
| --- | --- | --- | --- |
| `resource` | 0 | 4 | The table id above, `u32` little-endian |
| `reader_identity` | 4 | 32 | SHA-256 over `slime-resource-reader-v1`, the name length as `u16` LE, and the instance name |

Rows are sorted strictly by `(resource, reader_identity)`. The decoder refuses
an unknown resource id, a zero identity, a duplicate row, unsorted rows, unknown
required flags, and trailing bytes. At admission, the root refuses a second
object and a row that names no declared instance.
