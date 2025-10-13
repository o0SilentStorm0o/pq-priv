//! Unit tests for RocksDB integration with real database.

use std::path::PathBuf;
use tempfile::TempDir;

use storage::{DbTuning, Store, TipInfo};
use consensus::{Block, BlockHeader};
use num_bigint::BigUint;
use codec::to_vec_cbor;

/// Helper to create a temporary test store.
fn create_test_store() -> (Store, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let tuning = DbTuning::development(); // Fast for tests
    let store = Store::open_with_tuning(temp_dir.path(), tuning).unwrap();
    (store, temp_dir)
}

#[test]
fn test_open_create_cfs() {
    let temp_dir = TempDir::new().unwrap();
    let tuning = DbTuning::default();
    
    // Create database
    let store = Store::open_with_tuning(temp_dir.path(), tuning.clone()).unwrap();
    drop(store);
    
    // Reopen - should not fail
    let store2 = Store::open_with_tuning(temp_dir.path(), tuning).unwrap();
    
    // Verify tip is None on fresh DB
    assert!(store2.tip().unwrap().is_none());
}

#[test]
fn test_batch_atomicity() {
    let (store, _temp_dir) = create_test_store();
    
    // Create a simple tip
    let tip = TipInfo::new(
        1,
        [42u8; 32],
        BigUint::from(1000u64),
        0,
    );
    
    // Write tip
    store.set_tip_meta(&tip).unwrap();
    
    // Read back
    let read_tip = store.tip().unwrap().expect("tip should exist");
    assert_eq!(read_tip.height, 1);
    assert_eq!(read_tip.hash, [42u8; 32]);
    assert_eq!(read_tip.cumulative_work, BigUint::from(1000u64));
}

#[test]
fn test_reopen_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let tuning = DbTuning::development();
    
    let test_hash = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                     0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20];
    
    // First session: write tip
    {
        let store = Store::open_with_tuning(temp_dir.path(), tuning.clone()).unwrap();
        let tip = TipInfo::new(
            42,
            test_hash,
            BigUint::from(999999u64),
            5,
        );
        store.set_tip_meta(&tip).unwrap();
    }
    
    // Second session: verify persistence
    {
        let store = Store::open_with_tuning(temp_dir.path(), tuning).unwrap();
        let tip = store.tip().unwrap().expect("tip should persist");
        assert_eq!(tip.height, 42);
        assert_eq!(tip.hash, test_hash);
        assert_eq!(tip.cumulative_work, BigUint::from(999999u64));
        assert_eq!(tip.reorg_count, 5);
    }
}

#[test]
fn test_utxo_reset() {
    let (store, _temp_dir) = create_test_store();
    
    // Initially empty
    let count = store.utxo_len().unwrap();
    assert_eq!(count, 0);
    
    // Reset should not panic
    store.reset_utxo().unwrap();
    
    let count_after = store.utxo_len().unwrap();
    assert_eq!(count_after, 0);
}

#[test]
fn test_write_reopen_read() {
    let temp_dir = TempDir::new().unwrap();
    let tuning = DbTuning::development();
    
    let test_hash = [0xaa; 32];
    
    // Session 1: Write some data
    {
        let store = Store::open_with_tuning(temp_dir.path(), tuning.clone()).unwrap();
        let tip = TipInfo::new(
            100,
            test_hash,
            BigUint::from(12345u64),
            0,
        );
        store.set_tip_meta(&tip).unwrap();
        
        // Verify write
        let read_tip = store.tip().unwrap().unwrap();
        assert_eq!(read_tip.height, 100);
    }
    
    // Session 2: Reopen and read
    {
        let store = Store::open_with_tuning(temp_dir.path(), tuning).unwrap();
        let tip = store.tip().unwrap().expect("data should persist across restarts");
        assert_eq!(tip.height, 100);
        assert_eq!(tip.hash, test_hash);
        assert_eq!(tip.cumulative_work, BigUint::from(12345u64));
    }
}

#[test]
fn test_tuning_env_override() {
    std::env::set_var("PQPRIV_DB_WRITE_BUFFER_MB", "512");
    std::env::set_var("PQPRIV_DB_BLOCK_CACHE_MB", "1024");
    std::env::set_var("PQPRIV_DB_COMPRESSION", "lz4");
    
    let tuning = DbTuning::default().from_env();
    
    assert_eq!(tuning.write_buffer_mb(), 512);
    assert_eq!(tuning.block_cache_mb(), 1024);
    assert_eq!(tuning.compression(), "lz4");
    
    std::env::remove_var("PQPRIV_DB_WRITE_BUFFER_MB");
    std::env::remove_var("PQPRIV_DB_BLOCK_CACHE_MB");
    std::env::remove_var("PQPRIV_DB_COMPRESSION");
}

#[test]
fn test_clear_tip() {
    let (store, _temp_dir) = create_test_store();
    
    // Write tip
    let tip = TipInfo::new(10, [0xff; 32], BigUint::from(1000u64), 0);
    store.set_tip_meta(&tip).unwrap();
    assert!(store.tip().unwrap().is_some());
    
    // Clear tip
    store.clear_tip_meta().unwrap();
    assert!(store.tip().unwrap().is_none());
}
