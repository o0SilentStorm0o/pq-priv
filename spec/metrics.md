# Prometheus Metrics

The JSON-RPC server exposes a `/metrics` endpoint that emits a Prometheus text
payload describing the node’s current state. Metrics originate from the mempool,
chainstate, and RocksDB statistics gathered inside `RpcContext::metrics_snapshot`.

| Metric | Type | Description |
| ------ | ---- | ----------- |
| `pqpriv_peers` | gauge | Number of peers currently connected according to `NetworkHandle::peer_info`. |
| `pqpriv_tip_height` | gauge | Height of the active chain tip. |
| `pqpriv_cumulative_work` | gauge | Total cumulative work of the active tip rendered as a float for dashboards. |
| `pqpriv_current_target` | gauge | Compact difficulty target (`nBits`) of the tip header. |
| `pqpriv_mempool_size` | gauge | Count of transactions stored in the mempool (excludes orphans). |
| `pqpriv_mempool_bytes` | gauge | Total serialised size of transactions held in the mempool. |
| `pqpriv_orphan_count` | gauge | Number of orphan transactions awaiting missing parents. |
| `pqpriv_db_compactions` | gauge | RocksDB compaction jobs reported by `ChainState::db_stats`. |
| `pqpriv_reorg_count` | counter | Total observed reorganisations since genesis. |
| `pqpriv_batch_commit_ms` | gauge | Duration of the most recent block batch commit (milliseconds). |

## Scraping

The endpoint is served by Axum and bound to the configured RPC address. A sample
Prometheus scrape job:

```yaml
scrape_configs:
  - job_name: pqpriv
    static_configs:
      - targets: ['localhost:8645']
```

## Extensibility

New gauges can be added by extending `MetricsSnapshot` inside `crates/node/src/rpc.rs`.
Be mindful to keep metric names snake_case with a `pqpriv_` prefix to avoid
collisions with third-party exporters.
