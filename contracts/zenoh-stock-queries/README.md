# Zenoh stock-peer query fixtures

`v1/schema.zt` owns the file the queries exam hands from its checker to its Rust tests.
`scripts/check/check-zenoh-profile0.py --slice queries` writes `build/zenoh-queries/fixtures.zti` from the
captured bytes in `scripts/lib/zenoh_queries_exam.py`, validates it against this schema, and gives its path to
the `zenoh_queries::` tests in `ZENOH_QUERIES_FIXTURES`. `just zenoh_queries_gen` renders the same record as
`components/lib/src/zenoh_queries/fixtures.rs` through `v1/gen_rust.zt`. The tests read the constants that file
holds, not a hand-written parser.

The record is a container only. The wire is eclipse-zenoh's and the batches are bytes a stock
`eclipse-zenoh==1.0.0` peer sent, so the contract declares no layout for them. It fixes:

- `queryablePeer`: the eight batches a peer that declared a queryable on `slime_demo/query` and answered one
  query sent to a Profile 0 session, in the order it sent them;
- `getterPeer`: the six batches a peer that asked that query sent, in order;
- `refuse`: fifteen variants of those batches the profile must keep refusing, each built from them by one
  named change;
- the counts (8, 6 and 15) and the bounds a reader enforces before it allocates: a batch is at most 512 bytes,
  a name at most 64.

A record with another `formatVersion`, an odd or non-hexadecimal `hex`, a batch over the bound, or a field the
contract does not name, at the top level or in any row and however it is laid out, is refused. The decoder
closes the field set itself, because the derived `decode` ignores a field it does not know. The Rust reader is
part of the implementation, not this contract. The scope is the work item `zenoh-queryables`.
