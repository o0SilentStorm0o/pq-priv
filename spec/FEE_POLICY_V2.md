# Fee Policy v2 - STARK Proof CPU Cost Model

**Version**: 2.0  
**Date**: 2025-10-25  
**Status**: 🔍 DESIGN PHASE

---

## Problem Statement

STARK proof verification is CPU-intensive (~18-20ms per proof). Without fee policy, attackers can:
- Spam mempool with invalid proofs (DoS attack)
- Force nodes to waste CPU on verification
- Congest network with heavy transactions

**Current Gap**: No fee differentiation between light/heavy transactions.

---

## Design: CPU-Proportional Fees

### Base Fee Structure

```rust
pub struct TransactionFee {
    pub base_fee: u64,        // Minimal fee (1000 satoshis)
    pub proof_fee: u64,       // STARK verification cost (5000 satoshis)
    pub size_fee: u64,        // Per-byte cost (10 satoshis/byte)
}
```

**Rationale**:
- `base_fee`: Covers basic TX processing (sig verify, UTXO lookup)
- `proof_fee`: Covers STARK verification CPU cost (~18ms @ 3GHz = ~54M cycles)
- `size_fee`: Covers bandwidth/storage cost

### Fee Formula

```
total_fee = base_fee + proof_fee + (tx_size_bytes * size_fee)
```

**Example**:
- Light TX (no STARK): 1000 + 0 + (250 * 10) = 3500 satoshis
- Heavy TX (STARK): 1000 + 5000 + (1500 * 10) = 21000 satoshis

**Economics**:
- Heavy TX costs ~6x more than light TX
- Aligns with CPU cost ratio (20ms vs 1ms)
- Makes spam expensive (~$0.02 per STARK TX @ $100K BTC)

---

## Mempool CPU Caps

### Per-Block Limits

```rust
pub struct MempoolLimits {
    pub max_stark_proofs_per_block: usize,  // 50 proofs max
    pub max_cpu_ms_per_block: u64,          // 1000ms total
    pub max_mempool_stark_proofs: usize,    // 200 proofs queued
}
```

**Block CPU Budget**:
- Target block time: 10 seconds
- Max verification time: 1000ms (10% of block time)
- 50 STARK proofs × 20ms = 1000ms
- Remaining 9 seconds for consensus/network/mining

**Mempool Queueing**:
- Priority queue by fee density (satoshis per CPU-ms)
- Evict lowest-fee TXs when limit reached
- Prevents mempool exhaustion

### Fee Density Calculation

```rust
fn fee_density(tx: &Transaction) -> f64 {
    let cpu_cost_ms = if tx.has_stark_proof() { 20.0 } else { 1.0 };
    tx.total_fee() as f64 / cpu_cost_ms
}
```

**Priority**:
1. High fee density → fast inclusion
2. Low fee density → slow inclusion / eviction
3. Zero fee → immediate reject

---

## Implementation Plan

### Phase 1: Fee Validation (Mempool)

**File**: `crates/node/src/mempool.rs`

```rust
impl Mempool {
    pub fn validate_fee(&self, tx: &Transaction) -> Result<(), MempoolError> {
        let required_fee = self.calculate_required_fee(tx);
        if tx.fee < required_fee {
            return Err(MempoolError::InsufficientFee {
                required: required_fee,
                provided: tx.fee,
            });
        }
        Ok(())
    }
    
    fn calculate_required_fee(&self, tx: &Transaction) -> u64 {
        let base = 1000;
        let proof = if tx.has_stark_proof() { 5000 } else { 0 };
        let size = tx.serialized_size() * 10;
        base + proof + size
    }
}
```

### Phase 2: CPU Caps (Block Validation)

**File**: `crates/node/src/mempool.rs`

```rust
impl Mempool {
    pub fn select_transactions_for_block(&self) -> Vec<Transaction> {
        let mut selected = Vec::new();
        let mut cpu_budget_ms = 1000;
        let mut stark_count = 0;
        
        // Priority queue by fee density
        let mut candidates: Vec<_> = self.pool.values().collect();
        candidates.sort_by(|a, b| {
            fee_density(b).partial_cmp(&fee_density(a)).unwrap()
        });
        
        for tx in candidates {
            let cpu_cost = if tx.has_stark_proof() { 20 } else { 1 };
            
            // Check limits
            if tx.has_stark_proof() && stark_count >= 50 {
                continue; // STARK limit reached
            }
            if cpu_budget_ms < cpu_cost {
                break; // CPU budget exhausted
            }
            
            selected.push(tx.clone());
            cpu_budget_ms -= cpu_cost;
            if tx.has_stark_proof() {
                stark_count += 1;
            }
        }
        
        selected
    }
}
```

### Phase 3: Fee Estimation API

**File**: `crates/node/src/rpc.rs`

```rust
pub async fn estimate_fee(tx: Transaction) -> FeeEstimate {
    let base = 1000;
    let proof = if tx.has_stark_proof() { 5000 } else { 0 };
    let size = tx.serialized_size() * 10;
    
    FeeEstimate {
        minimum: base + proof + size,
        recommended: (base + proof + size) * 120 / 100,  // +20% for priority
        fast: (base + proof + size) * 150 / 100,         // +50% for fast inclusion
    }
}
```

---

## Testing Strategy

### Unit Tests

```rust
#[test]
fn test_stark_fee_higher_than_regular() {
    let light_tx = create_regular_tx();
    let heavy_tx = create_stark_tx();
    
    assert!(calculate_fee(&heavy_tx) > calculate_fee(&light_tx));
}

#[test]
fn test_mempool_rejects_low_fee_stark() {
    let tx = create_stark_tx_with_fee(100); // Too low
    let result = mempool.add(tx);
    assert!(matches!(result, Err(MempoolError::InsufficientFee { .. })));
}

#[test]
fn test_block_respects_cpu_cap() {
    // Add 100 STARK TXs to mempool
    for i in 0..100 {
        mempool.add(create_stark_tx());
    }
    
    let block_txs = mempool.select_transactions_for_block();
    
    // Should select max 50 due to CPU cap
    assert!(block_txs.len() <= 50);
}
```

### Integration Tests

```rust
#[test]
fn test_dos_resistance() {
    // Attacker spams 1000 STARK TXs with minimum fee
    for i in 0..1000 {
        mempool.add(create_stark_tx_with_min_fee());
    }
    
    // Honest user submits high-fee TX
    let priority_tx = create_stark_tx_with_fee(10000);
    mempool.add(priority_tx.clone());
    
    let block_txs = mempool.select_transactions_for_block();
    
    // Priority TX should be included despite spam
    assert!(block_txs.contains(&priority_tx));
}
```

---

## Security Analysis

### Attack Vectors

1. **Mempool Spam**
   - Mitigation: Fee validation + mempool size cap
   - Cost: 21000 satoshis per STARK TX = $21 @ $100K BTC
   - To fill 200-TX mempool: $4200

2. **Block Stuffing**
   - Mitigation: CPU budget (max 50 STARK/block)
   - Cost: 50 × 21000 = 1,050,000 satoshis = $1050 per block
   - To sustain 1 hour: $6300 (economically infeasible)

3. **Fee Market Manipulation**
   - Mitigation: Priority queue ensures highest bidders win
   - Honest users can always outbid attackers

### Performance Impact

- **Mempool overhead**: O(n log n) sort per block (negligible)
- **Fee validation**: ~10μs per TX (negligible)
- **CPU cap enforcement**: O(1) counter (negligible)

---

## Migration Path

1. ✅ Design fee policy (this document)
2. ⏳ Implement fee calculation in mempool
3. ⏳ Add CPU cap enforcement
4. ⏳ Write comprehensive tests
5. ⏳ Deploy to testnet
6. ⏳ Monitor fee market dynamics
7. ⏳ Adjust parameters if needed

---

## Open Questions

1. **Fee adjustment**: Should fees be dynamic based on mempool congestion?
   - Pros: Better price discovery
   - Cons: Complexity, unpredictability
   - Decision: Start with static fees, add dynamics later if needed

2. **STARK verification parallelization**: Can we verify multiple proofs concurrently?
   - Current: Sequential verification
   - Future: Rayon-based parallel verification (already implemented in batch.rs)
   - Impact: Could increase block capacity to 200+ STARK TXs

3. **Fee burning**: Should STARK fees be burned to create deflationary pressure?
   - Pros: Aligns with privacy value prop
   - Cons: Reduces miner incentives
   - Decision: TBD (需ユーザーフィードバック)

---

## References

- Bitcoin fee market: [BIP 125 (RBF)](https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki)
- Ethereum gas model: [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)
- STARK benchmarks: `crates/crypto/stark/CONSTANT_TIME_AUDIT.md`
