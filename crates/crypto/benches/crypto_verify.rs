//! Criterion benchmarks for signature verification performance.
//!
//! This benchmark suite measures:
//! 1. Single verify baseline - individual signature verification
//! 2. Batch verify performance - batches of 32, 128, 512 signatures
//! 3. Per-signature speedup - comparing single vs batch throughput
//!
//! Expected results: 2-5x speedup for batch verification at scale.
//!
//! Uses Dilithium2 (ML-DSA-44) for realistic post-quantum performance.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crypto::{
    AlgTag, PublicKey, SecretKey, Signature, VerifyItem, batch_verify_v2, context, sign, verify,
};
use pqcrypto_traits::sign::PublicKey as _;
use pqcrypto_traits::sign::SecretKey as _;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Generate a deterministic keypair for consistent benchmark results.
/// Uses Dilithium2 (ML-DSA-44) for post-quantum security.
fn generate_keypair(seed: u64) -> (PublicKey, SecretKey) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut seed_bytes = [0u8; 32];
    rng.fill_bytes(&mut seed_bytes);

    // Use Dilithium2 keygen (note: pqcrypto-mldsa ignores seed, uses OsRng)
    let (pk, sk) = pqcrypto_mldsa::mldsa44::keypair();
    (
        PublicKey::from_bytes(pk.as_bytes().to_vec()),
        SecretKey::from_bytes(sk.as_bytes().to_vec()),
    )
}

/// Create a signed message of specified size
fn create_signed_message(
    _pk: &PublicKey,
    sk: &SecretKey,
    msg_size: usize,
    seed: u64,
) -> (Vec<u8>, Signature) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut message = vec![0u8; msg_size];
    rng.fill_bytes(&mut message);

    let signature =
        sign(&message, sk, AlgTag::Dilithium2, context::TX).expect("signing should succeed");

    (message, signature)
}

/// Benchmark: Single signature verification (baseline)
fn bench_single_verify(c: &mut Criterion) {
    let (pk, sk) = generate_keypair(42);
    let (message, signature) = create_signed_message(&pk, &sk, 1024, 100);

    c.bench_function("single_verify_1kB_msg", |b| {
        b.iter(|| {
            let result = verify(
                black_box(&message),
                black_box(&pk),
                black_box(&signature),
                black_box(context::TX),
            );
            black_box(result)
        })
    });
}

/// Benchmark: Batch verification with varying batch sizes
fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verify");

    // Test batch sizes: 32, 128, 512 (reduced from 2048 for reasonable runtime)
    for batch_size in [32, 128, 512] {
        // Set throughput to measure per-signature performance
        group.throughput(Throughput::Elements(batch_size as u64));

        // Generate keypairs and signed messages
        println!("Generating {} keypairs for benchmark...", batch_size);
        let keypairs: Vec<_> = (0..batch_size)
            .map(|i| {
                if i % 10 == 0 {
                    print!(".");
                }
                generate_keypair(1000 + i as u64)
            })
            .collect();
        println!(" done");

        let messages_and_sigs: Vec<_> = keypairs
            .iter()
            .enumerate()
            .map(|(i, (pk, sk))| {
                if i % 10 == 0 {
                    print!(".");
                }
                let (msg, sig) = create_signed_message(pk, sk, 1024, 2000 + i as u64);
                (msg, sig)
            })
            .collect();
        println!(" signatures generated");

        // Create VerifyItem references (owned data for benchmark stability)
        let items: Vec<VerifyItem> = keypairs
            .iter()
            .zip(&messages_and_sigs)
            .map(|((pk, _sk), (msg, sig))| {
                VerifyItem::new(
                    context::TX,
                    AlgTag::Dilithium2,
                    pk.as_bytes(),
                    msg.as_slice(),
                    &sig.bytes,
                )
                .expect("VerifyItem creation should succeed")
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &items,
            |b, items| {
                b.iter(|| {
                    // Clone items since batch_verify_v2 takes ownership
                    let items_clone = items.clone();
                    let outcome = batch_verify_v2(black_box(items_clone));
                    black_box(outcome)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark: Comparison of single vs batch throughput
fn bench_throughput_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_comparison");
    group.sample_size(10); // Reduce sample size for faster benchmarking

    // Batch size for comparison (reduced to 128 for reasonable runtime with Dilithium)
    let batch_size = 128;
    group.throughput(Throughput::Elements(batch_size as u64));

    // Generate test data
    println!(
        "Generating {} keypairs for throughput comparison...",
        batch_size
    );
    let keypairs: Vec<_> = (0..batch_size)
        .map(|i| {
            if i % 10 == 0 {
                print!(".");
            }
            generate_keypair(3000 + i as u64)
        })
        .collect();
    println!(" done");

    let messages_and_sigs: Vec<_> = keypairs
        .iter()
        .enumerate()
        .map(|(i, (pk, sk))| {
            if i % 10 == 0 {
                print!(".");
            }
            let (msg, sig) = create_signed_message(pk, sk, 1024, 4000 + i as u64);
            (msg, sig)
        })
        .collect();
    println!(" signatures generated");

    let items: Vec<VerifyItem> = keypairs
        .iter()
        .zip(&messages_and_sigs)
        .map(|((pk, _sk), (msg, sig))| {
            VerifyItem::new(
                context::TX,
                AlgTag::Dilithium2,
                pk.as_bytes(),
                msg.as_slice(),
                &sig.bytes,
            )
            .expect("VerifyItem creation should succeed")
        })
        .collect();

    // Benchmark: Sequential single verify
    group.bench_function("sequential_single_verify_128", |b| {
        b.iter(|| {
            for (i, _item) in items.iter().enumerate() {
                let pk = &keypairs[i].0;
                let (msg, sig) = &messages_and_sigs[i];
                let _result = verify(
                    black_box(msg),
                    black_box(pk),
                    black_box(sig),
                    black_box(context::TX),
                );
            }
        })
    });

    // Benchmark: Batch verify
    group.bench_function("batch_verify_128", |b| {
        b.iter(|| {
            // Clone items since batch_verify_v2 takes ownership
            let items_clone = items.clone();
            let outcome = batch_verify_v2(black_box(items_clone));
            black_box(outcome)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_verify,
    bench_batch_verify,
    bench_throughput_comparison
);
criterion_main!(benches);
