# Fork Choice & Sync Pipeline

This document outlines how PQ-PRIV selects the canonical chain, applies blocks,
recovers from reorganisations, and drives the header/block sync pipeline added in
Sprint 3.

## Chain indexing

`ChainState` maintains an in-memory index keyed by block hash. Each `BlockEntry`
contains the block, its height, cumulative work, parent hash, and an `active`
flag. The node consults this index to:

- determine the best tip (highest cumulative work, tie-broken by arrival);
- construct block locators for peers (`block_locator()`);
- stream block bodies during `getdata` handling;
- rebuild the active chain on restart using RocksDB contents.

Whenever a block is connected the node computes its work, updates the index,
records undo data, and persists headers/blocks/tip metadata inside a
`BlockBatch`.

## Reorganisation algorithm

Reorg handling is encapsulated in `ChainState::perform_reorg`:

1. Walk the candidate tip’s ancestors to find the lowest common ancestor (LCA)
   with the current active tip.
2. Collect hashes to detach (old tip back to but excluding the LCA) and hashes
   to attach (LCA child down to the new tip).
3. If a mempool is attached, collect transaction IDs confirmed on the attach
   side and transactions from the detached side to reintroduce later.
4. Apply a RocksDB batch that sequentially undoes detached blocks and reapplies
   the attach set, updating `undo_cache` entries in the process.
5. Update the active chain vector, tip hash, tip height, cumulative work, and
   persisted `TipInfo`. Increment `reorg_count`, record the commit duration, and
   trigger snapshotting when configured.
6. Publish a `ChainEvent::TipUpdated` broadcast so subscribers (RPC, sync, etc.)
   observe the new tip.
7. Remove now-confirmed transactions from the mempool, then reintroduce
   transactions from orphaned blocks in canonical order while skipping any that
   became confirmed on the winning side.

The algorithm ensures on-disk state, in-memory indices, and the mempool remain
consistent after any fork switch.

## Sync pipeline

Synchronization is split across cooperative Tokio tasks:

- **Peer event loop** (`tasks::run_peer_event_loop`) subscribes to P2P
  `PeerEvent`s, forwarding inbound inventory, header, and block messages to
  `Relay`/`SyncManager`, answering header/data requests, and responding to pings.
- **Chain event loop** (`tasks::run_chain_event_loop`) subscribes to
  `ChainEvent::TipUpdated`, registering fresh headers with `SyncManager` so
  outstanding block downloads continue smoothly and peer best heights are
  updated via `NetworkHandle::update_best_height`.
- **Periodic locator broadcast** (`tasks::run_block_sync_task`) snapshots the
  local locator every ten seconds and broadcasts a `getheaders` to nudge peers
  when the node lags behind.

`SyncManager` reacts to inventories by asking for unknown headers, scheduling
block downloads for newly announced hashes, and feeding bodies into the
`ChainState` once validation succeeds. Peer heights recorded through
`update_best_height` provide visibility into network progress and inform the
block sync strategy.

## Shutdown behaviour

All tasks listen for broadcast closures or runtime cancellation so they exit
cleanly when the async runtime receives a shutdown signal. Database batches are
committed atomically, allowing the node to restart without replaying historical
P2P traffic.
