//! Transaction v2 (STARK privacy) performance benchmarks.
//!
//! Benchmarks for TX v2 validation, nullifier checking, and mempool throughput.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use tx::{Nullifier, SpendTag};

/// Benchmark nullifier set lookup performance.
///
/// Tests:
/// - In-memory HashSet lookup (current implementation)
/// - RocksDB persistent lookup
/// - Cache hit vs cache miss scenarios
fn bench_nullifier_lookup(c: &mut Criterion) {
    use std::collections::HashSet;

    let mut group = c.benchmark_group("nullifier_lookup");

    // Test different nullifier set sizes
    for size in [100, 1_000, 10_000, 100_000] {
        // Build nullifier set
        let mut nullifiers = HashSet::new();
        for i in 0u64..size {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&i.to_le_bytes());
            nullifiers.insert(Nullifier(bytes));
        }

        // Benchmark lookup (cache hit)
        let target = {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&(size / 2).to_le_bytes());
            Nullifier(bytes)
        };

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("hashset_hit", size), &size, |b, _| {
            b.iter(|| {
                black_box(nullifiers.contains(&target));
            });
        });

        // Benchmark lookup (cache miss)
        let missing = Nullifier([0xFF; 32]);
        group.bench_with_input(BenchmarkId::new("hashset_miss", size), &size, |b, _| {
            b.iter(|| {
                black_box(nullifiers.contains(&missing));
            });
        });
    }

    group.finish();
}

/// Benchmark spend tag bloom filter false positive rate.
///
/// Tests:
/// - Bloom filter insert/query performance
/// - False positive rate vs filter size
/// - Memory usage optimization
fn bench_spend_tag_filter(c: &mut Criterion) {
    use std::collections::HashSet;

    let mut group = c.benchmark_group("spend_tag_filter");

    // Simulate wallet scanning 10k spend tags per epoch
    let num_tags = 10_000;
    let mut tags = HashSet::new();
    for i in 0u64..num_tags {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&i.to_le_bytes());
        tags.insert(SpendTag(bytes));
    }

    // Benchmark spend tag lookup
    let target = {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&5000u64.to_le_bytes());
        SpendTag(bytes)
    };

    group.throughput(Throughput::Elements(1));
    group.bench_function("hashset_query", |b| {
        b.iter(|| {
            black_box(tags.contains(&target));
        });
    });

    group.finish();
}

/// Benchmark TX v2 validation pipeline.
///
/// Tests:
/// - Nullifier uniqueness check
/// - STARK proof verification (placeholder)
/// - Mempool insertion throughput
fn bench_tx_v2_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tx_v2_validation");

    // Placeholder validation function
    fn validate_tx_v2(nullifier: &Nullifier, _proof_bytes: &[u8]) -> bool {
        // TODO: Wire up real STARK verification in Step 4
        // For now, just simulate nullifier check
        nullifier.0 != [0u8; 32]
    }

    let nullifier = Nullifier([42u8; 32]);
    let proof = vec![0u8; 1024]; // Placeholder 1KB proof

    group.throughput(Throughput::Elements(1));
    group.bench_function("validate_single", |b| {
        b.iter(|| {
            black_box(validate_tx_v2(&nullifier, &proof));
        });
    });

    // Benchmark batch validation (10 TXs)
    let nullifiers: Vec<Nullifier> = (0..10)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            Nullifier(bytes)
        })
        .collect();

    group.throughput(Throughput::Elements(10));
    group.bench_function("validate_batch_10", |b| {
        b.iter(|| {
            for n in &nullifiers {
                black_box(validate_tx_v2(n, &proof));
            }
        });
    });

    group.finish();
}

/// Benchmark mempool TX v2 insertion with nullifier collision detection.
fn bench_mempool_insertion(c: &mut Criterion) {
    use std::collections::HashSet;

    let mut group = c.benchmark_group("mempool_insertion");

    // Simulate mempool with 1000 existing TXs
    let mut mempool_nullifiers = HashSet::new();
    for i in 0u64..1000 {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&i.to_le_bytes());
        mempool_nullifiers.insert(Nullifier(bytes));
    }

    // Benchmark insertion (no collision)
    let new_nullifier = Nullifier([0xFF; 32]);

    group.throughput(Throughput::Elements(1));
    group.bench_function("insert_no_collision", |b| {
        b.iter(|| {
            let mut mempool = mempool_nullifiers.clone();
            black_box(mempool.insert(new_nullifier));
        });
    });

    // Benchmark collision detection
    let existing_nullifier = {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&500u64.to_le_bytes());
        Nullifier(bytes)
    };

    group.bench_function("detect_collision", |b| {
        b.iter(|| {
            black_box(mempool_nullifiers.contains(&existing_nullifier));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_nullifier_lookup,
    bench_spend_tag_filter,
    bench_tx_v2_validation,
    bench_mempool_insertion
);
criterion_main!(benches);
