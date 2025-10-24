//! Criterion benchmarks for range proof performance.
//!
//! This benchmark suite measures:
//! 1. Single prove - creating individual range proofs
//! 2. Single verify - verifying individual range proofs
//! 3. Batch verify - verifying batches of 10, 50, 100 range proofs
//! 4. Per-proof speedup - comparing single vs batch throughput
//!
//! Expected results: 2-5x speedup for batch verification at scale.
//!
//! Uses Bulletproofs+ for 64-bit range proofs.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crypto::{Commitment, RangeProof, commit_value, prove_range, verify_range};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Generate deterministic test data for range proofs
fn generate_proof_data(seed: u64) -> (u64, [u8; 32], Commitment, RangeProof) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    // Generate random value in valid range (0 to 2^64-1)
    let value = rng.next_u64();

    // Generate random blinding factor
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);

    // Create commitment
    let commitment = commit_value(value, &blinding);

    // Create proof
    let proof = prove_range(value, &blinding).expect("proof generation should succeed");

    (value, blinding, commitment, proof)
}

/// Benchmark: Single range proof generation
fn bench_prove_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_prove");

    // Test with different value sizes
    for &bits in &[16, 32, 64] {
        group.bench_with_input(
            BenchmarkId::new("prove", format!("{}_bit", bits)),
            &bits,
            |b, _| {
                let mut rng = ChaCha20Rng::seed_from_u64(42);

                // Generate value in appropriate range
                let value = if bits == 64 {
                    rng.next_u64()
                } else {
                    let max_value = (1u64 << bits) - 1;
                    rng.next_u64() % (max_value + 1)
                };

                let mut blinding = [0u8; 32];
                rng.fill_bytes(&mut blinding);

                b.iter(|| {
                    let proof = prove_range(black_box(value), black_box(&blinding));
                    black_box(proof)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark: Single range proof verification
fn bench_verify_range(c: &mut Criterion) {
    let (_, _, commitment, proof) = generate_proof_data(100);

    c.bench_function("range_proof_verify_single", |b| {
        b.iter(|| {
            let result = verify_range(black_box(&commitment), black_box(&proof));
            black_box(result)
        })
    });
}

/// Benchmark: Batch range proof verification with varying batch sizes
fn bench_batch_verify_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_batch_verify");

    // Test batch sizes: 10, 50, 100 (reasonable for blockchain blocks)
    for batch_size in [10, 50, 100] {
        group.throughput(Throughput::Elements(batch_size as u64));

        // Generate proofs
        println!("Generating {} range proofs for benchmark...", batch_size);
        let proofs_data: Vec<_> = (0..batch_size)
            .map(|i| {
                if i % 10 == 0 {
                    print!(".");
                }
                generate_proof_data(1000 + i as u64)
            })
            .collect();
        println!(" done");

        // Benchmark: Sequential verification
        group.bench_with_input(
            BenchmarkId::new("sequential", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    let results: Vec<bool> = proofs_data
                        .iter()
                        .map(|(_, _, commit, proof)| {
                            verify_range(black_box(commit), black_box(proof))
                        })
                        .collect();
                    black_box(results)
                })
            },
        );

        // Benchmark: Parallel verification using rayon
        group.bench_with_input(
            BenchmarkId::new("parallel", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    use rayon::prelude::*;
                    let results: Vec<bool> = proofs_data
                        .par_iter()
                        .map(|(_, _, commit, proof)| {
                            verify_range(black_box(commit), black_box(proof))
                        })
                        .collect();
                    black_box(results)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark: Throughput comparison - single vs batch
fn bench_throughput_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_throughput");

    let batch_size = 100;
    group.throughput(Throughput::Elements(batch_size as u64));

    println!(
        "Generating {} range proofs for throughput benchmark...",
        batch_size
    );
    let proofs_data: Vec<_> = (0..batch_size)
        .map(|i| generate_proof_data(2000 + i as u64))
        .collect();
    println!(" done");

    // Single verification (baseline)
    group.bench_function("baseline_single_verify", |b| {
        b.iter(|| {
            let results: Vec<bool> = proofs_data
                .iter()
                .map(|(_, _, commit, proof)| verify_range(black_box(commit), black_box(proof)))
                .collect();
            black_box(results)
        })
    });

    // Parallel verification
    group.bench_function("optimized_parallel_verify", |b| {
        b.iter(|| {
            use rayon::prelude::*;
            let results: Vec<bool> = proofs_data
                .par_iter()
                .map(|(_, _, commit, proof)| verify_range(black_box(commit), black_box(proof)))
                .collect();
            black_box(results)
        })
    });

    group.finish();
}

/// Benchmark: Proof size analysis
fn bench_proof_size(c: &mut Criterion) {
    c.bench_function("range_proof_size_measurement", |b| {
        b.iter(|| {
            let (value, blinding, _, _) = generate_proof_data(42);
            let proof =
                prove_range(black_box(value), black_box(&blinding)).expect("proof should succeed");

            let size = proof.proof_bytes.len();
            black_box(size)
        })
    });
}

criterion_group!(
    benches,
    bench_prove_range,
    bench_verify_range,
    bench_batch_verify_range,
    bench_throughput_comparison,
    bench_proof_size,
);
criterion_main!(benches);
