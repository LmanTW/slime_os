# Zenoh stock-peer query fixtures

`v1/schema.zt` owns the file the queries exam hands from its checker to its Rust tests.
`scripts/check/check-zenoh-profile0.py --slice queries` writes `build/zenoh-queries/fixtures.zti` from the
captured bytes in `scripts/lib/zenoh_queries_exam.py`, validates it against this schema, and gives its path to
the `zenoh_queries::` tests. `just zenoh_queries_gen` renders the same record as Rust constants through
`v1/gen_rust.zt`. The tests read them through generated bindings, not a hand-written parser.

The record is a container only. The wire is eclipse-zenoh's, and the batches are bytes a stock
`eclipse-zenoh==1.0.0` peer sent, so the contract declares no layout for them. It fixes the captured batches in
the order the peers sent them, the variants the profile must keep refusing, their counts, and the bounds a reader
enforces before it allocates.

A record with another `formatVersion`, an odd or non-hexadecimal `hex`, a batch over the bound, or a field the
contract does not name is refused. The scope is the work item `zenoh-queryables`.
