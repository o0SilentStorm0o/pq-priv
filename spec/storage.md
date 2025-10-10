# Storage Layout

Sprint 3 introduced persistent chainstate backed by RocksDB. This document
summarises the column families, key encodings, and lifecycle hooks that the node
uses when applying blocks, handling reorganisations, and maintaining snapshots.

## Column families

The node opens RocksDB with five column families, each with a single-byte prefix
so keys remain sorted lexicographically:

| Column family | Prefix | Contents |
| ------------- | ------ | -------- |
| `HEADERS`     | `H`    | Canonical headers encoded as CBOR and keyed by height (`H‖height_be`). |
| `BLOCKS`      | `B`    | Full block bodies keyed by block hash (`B‖hash`). |
| `UTXO`        | `U`    | Encoded `OutputRecord` entries for the active UTXO set keyed by outpoint (`U‖txid‖vout_be`). |
| `LINKTAG`     | `L`    | Privacy link-tag bloom helpers keyed by 32-byte tags (`L‖tag`). |
| `META`        | `M`    | Tip metadata, compact-index counters, and snapshot hints keyed by ASCII names (`M‖name`). |

Each column family is created automatically when the database is opened. The
node uses typed helpers from `crates/storage::schema` to construct and parse
keys, ensuring endianness stays consistent across components.

## Tip metadata (`META`)

`META` stores a CBOR-serialised `TipMetadata` record under the `M‖tip` key. The
record mirrors `TipInfo`—height, hash, cumulative work (hex string), and the
number of observed reorganisations. Updates happen whenever:

- genesis is installed;
- a block is connected on the active chain;
- a reorg rewinds and replays blocks onto a new tip.

Additional metadata slots include:

- `M‖compact_index` – monotonic counter used to hand out compact indices for
  new UTXO commitments;
- future compatibility hooks (`schema_version`, `network`, `pow_limit`) stored
  for migrations.

## UTXO storage

The active UTXO set is materialised inside RocksDB so the node can restart
without replaying the entire chain. `RocksUtxoStore` implements the
`utxo::UtxoBackend` trait, mapping reads, inserts, and removals directly onto the
`UTXO` column family. Link tags are recorded alongside the same write batch so
privacy-preserving spends can detect duplicates across restarts.

During block application the node:

1. Opens a `BlockBatch`, obtaining a mutable UTXO backend.
2. Calls `utxo::apply_block`, which iterates the block’s transactions and writes
   outputs/deletes inputs inside the RocksDB batch.
3. Stages the block body, header, and updated tip metadata before committing.

Reorgs call `utxo::undo_block` with cached `BlockUndo` payloads to roll back
outpoints prior to replaying the competing chain.

## Snapshots and checkpoints

When snapshots are enabled via `ChainState::configure_snapshots`, the store uses
RocksDB checkpoints to capture a consistent copy of every column family at
configurable height intervals. Snapshot metadata is recorded alongside the tip
so restarts resume from the most recent checkpoint before replaying the tail of
blocks stored in `BLOCKS`.

## Database hygiene

`ChainState::db_stats` exposes `running_compactions`, allowing the `/metrics`
endpoint to surface background compaction pressure. Reorg commits also record the
elapsed write time (`last_commit_ms`), which is published as a Prometheus gauge
for operational visibility.
