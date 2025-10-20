# E2E Multi-Node Testing

This directory contains Docker Compose configurations for end-to-end multi-node testing of the PQ-PRIV blockchain node.

## 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+
- ~4 GB free disk space
- ~2 GB RAM per node

## 🏗️ Topologies

### 1. Linear Topology (`line.yml`)

**Scenario:** A → B → C chain synchronization

- `node_a`: Mines 1000 blocks
- `node_b`: Syncs from `node_a`
- `node_c`: Syncs from `node_b`

**Expected outcome:** All nodes reach same tip height and hash.

```bash
docker compose -f docker/e2e/line.yml up --build --abort-on-container-exit
```

**Ports:**
- node_a: P2P 9001, RPC 8545
- node_b: P2P 9002, RPC 8546
- node_c: P2P 9003, RPC 8547

### 2. Star Topology (`star.yml`)

**Scenario:** Hub ↔ Leaf1, Leaf2, Leaf3

- `hub`: Central mining node
- `leaf1`, `leaf2`, `leaf3`: Sync from hub

**Expected outcome:** All nodes converge to same tip, low orphan rate (<5%).

```bash
docker compose -f docker/e2e/star.yml up --build --abort-on-container-exit
```

**Ports:**
- hub: P2P 9010, RPC 8550
- leaf1: P2P 9011, RPC 8551
- leaf2: P2P 9012, RPC 8552
- leaf3: P2P 9013, RPC 8553

### 3. Partition + Reorg (`partition.yml`)

**Scenario:** Two isolated chains, then reconnect to trigger reorg

**Phase 1:** Isolated mining
```bash
# Start both isolated miners
docker compose -f docker/e2e/partition.yml up --build iso_a iso_b
```

- `iso_a`: Mines 200 blocks independently
- `iso_b`: Mines 250 blocks independently

**Phase 2:** Trigger reorg
```bash
# After both finish, start bridge node
docker compose -f docker/e2e/partition.yml up bridge
```

- `bridge`: Connects to both `iso_a` and `iso_b`
- **Expected:** `iso_a` reorgs to `iso_b`'s longer chain
- **Verification:** Both at height 250, `reorg_count_total` increments, orphan pool = 0

**Ports:**
- iso_a: P2P 9021, RPC 8560
- iso_b: P2P 9022, RPC 8561
- bridge: P2P 9023, RPC 8562

## 📊 Metrics Collection

Use the reporter script to collect metrics and verify consensus:

```bash
# After containers are running
./scripts/e2e-reporter.sh line 8545 8546 8547
./scripts/e2e-reporter.sh star 8550 8551 8552 8553
./scripts/e2e-reporter.sh partition 8560 8561 8562
```

The script generates `docker/e2e/report/summary_<topology>_<timestamp>.json` with:
- `tip_height` and `tip_hash` for each node
- `reorg_count_total` (reorg counter)
- `orphan_pool_size` (orphaned blocks)
- `db_size_bytes` (database size)
- `peer_count` (connected peers)

**Exit codes:**
- `0`: All nodes reached consensus (same tip_hash)
- `1`: Consensus failed (different tip_hash values)

## 🧪 Manual Testing

### Query node status

```bash
# Get chain tip
curl http://localhost:8545/chain/tip

# Get Prometheus metrics
curl http://localhost:8545/metrics | grep -E 'tip_height|reorg_count|orphan_pool'
```

### View logs

```bash
# Follow logs from all nodes
docker compose -f docker/e2e/line.yml logs -f

# Single node
docker logs pq_line_a -f
```

### Inspect database

```bash
# Enter container
docker exec -it pq_line_a /bin/bash

# Check data directory
ls -lh /data
du -sh /data
```

## 🧹 Cleanup

```bash
# Stop and remove containers
docker compose -f docker/e2e/line.yml down

# Remove data volumes
rm -rf docker/e2e/data/

# Remove all E2E artifacts
docker compose -f docker/e2e/line.yml down -v
docker compose -f docker/e2e/star.yml down -v
docker compose -f docker/e2e/partition.yml down -v
```

## 🐛 Troubleshooting

### Container fails to start

Check logs:
```bash
docker compose -f docker/e2e/line.yml logs node_a
```

Common issues:
- **Port already in use:** Change ports in compose file
- **Build fails:** Ensure Rust toolchain is up to date
- **Health check fails:** Verify RPC endpoint is responding

### Nodes don't sync

1. Check peer connections:
   ```bash
   curl http://localhost:8545/peers
   ```

2. Verify network connectivity:
   ```bash
   docker network inspect docker_e2e_line_net
   ```

3. Check for fork-choice issues in logs:
   ```bash
   docker logs pq_line_b | grep -i "reorg\|fork\|orphan"
   ```

### Metrics not available

Ensure RPC is listening on all interfaces:
```bash
docker exec pq_line_a netstat -tlnp | grep 8545
```

## 📈 Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `pqpriv_tip_height` | Gauge | Current blockchain height |
| `node_reorg_count_total` | Counter | Number of chain reorganizations |
| `node_orphan_pool_size` | Gauge | Orphaned blocks awaiting connection |
| `node_db_size_bytes` | Gauge | Total database size (SST + WAL) |
| `pqpriv_peers` | Gauge | Connected peer count |
| `node_block_validate_ms` | Histogram | Block validation time (P50/P95) |

## ✅ Definition of Done

### Linear Topology
- [ ] All 3 nodes reach height 1000
- [ ] Identical `tip_hash` across all nodes
- [ ] No panics or fatal errors in logs
- [ ] `orphan_pool_size = 0` on all nodes
- [ ] Report generated successfully

### Star Topology
- [ ] All 4 nodes converge to same tip
- [ ] Orphan rate < 5%
- [ ] No excessive reorgs (< 10 total)
- [ ] Report shows consensus

### Partition + Reorg
- [ ] `iso_a` reaches height 200
- [ ] `iso_b` reaches height 250
- [ ] Bridge triggers reorg on `iso_a`
- [ ] Final consensus at height 250
- [ ] `iso_a` shows `reorg_count_total >= 1`
- [ ] `orphan_pool_size = 0` after reorg
- [ ] Report confirms convergence

## 🔐 Security Notes

- `/metrics` endpoint is exposed for testing only
- In production, restrict to localhost or behind auth
- Data directories are ephemeral (docker volumes)
- No sensitive keys or credentials in test setup

## 🚀 Next Steps

After E2E tests pass:
1. Integrate into CI pipeline (`.github/workflows/e2e.yml`)
2. Add nightly large-scale snapshot tests
3. Implement automated DoD verification
4. Add performance benchmarks (block validation P95, sync throughput)
