# PR Checklist Report: `feat/storage-rocksdb-live`

Generated: 2025-10-14

## A) Kód a závislosti

- [x] **Zrušen stub:** ✅ V kořenovém `Cargo.toml` NEEXISTUJE `[patch.crates-io]`
  - Ověřeno: Patch sekce odstraněna
  - Commit: a925782

- [x] **Reálný RocksDB:** ✅ `crates/storage/Cargo.toml` používá správnou verzi
  ```toml
  rocksdb = { version = "0.22", default-features = false, features = ["lz4", "zstd", "multi-threaded-cf"] }
  ```

- [x] **Options builder:** ✅ Existuje v `crates/storage/src/store.rs`
  - Funkce: `build_db_options(tuning: &DbTuning) -> (Options, BlockBasedOptions)`
  - Nastavuje: `create_if_missing`, `increase_parallelism`, `level_compaction_dynamic_level_bytes`
  - Nastavuje: `target_file_size_base`, `write_buffer_size`, `bytes_per_sync`, `wal_bytes_per_sync`
  - Nastavuje: `compression_type` (Zstd/Lz4/None dle configu)
  - Nastavuje: `BlockBasedOptions` s LRU cache (konfigurovatelná velikost)
  - Nastavuje: `enable_pipelined_write(true)`

- [x] **Column Families:** ✅ Všech 5 CF explicitně inicializováno
  - HEADERS, BLOCKS, UTXO, LINKTAG, META
  - Používá `open_cf_descriptors` s explicitními deskriptory

- [x] **WriteBatch & WAL:** ✅ Atomické commity s WAL
  - `WriteBatch` v `batch.rs::commit()`
  - `opts.disable_wal(false)` v prod režimu
  - WAL konfigurovatelný přes `DbTuning::wal_enabled`

## B) Konfigurace (TOML/ENV/CLI)

- [x] **DbTuning struct:** ✅ Implementován v `crates/storage/src/config.rs` (235 řádků)
  - Pole: `max_background_jobs`, `write_buffer_mb`, `target_file_size_mb`
  - Pole: `compaction_dynamic`, `compression`, `bytes_per_sync_mb`
  - Pole: `wal_bytes_per_sync_mb`, `block_cache_mb`, `readahead_mb`
  - Pole: `enable_pipelined_write`, `wal_enabled`

- [x] **Výchozí hodnoty:** ✅ Implementovány v `Default::default()`
  - Dev/CI konzervativní: 4 jobs, 128MB buffer, 256MB cache
  - Také: `DbTuning::production()` a `DbTuning::development()`

- [x] **ENV override:** ✅ Metoda `from_env()` podporuje všechna pole
  - Prefix: `PQPRIV_DB_*`
  - Příklady: `PQPRIV_DB_WRITE_BUFFER_MB`, `PQPRIV_DB_BLOCK_CACHE_MB`
  - `PQPRIV_DB_COMPRESSION`, `PQPRIV_DB_WAL_ENABLED`

- [⚠️] **CLI přepínače:** ⚠️ **ZATÍM NEIMPLEMENTOVÁNY**
  - Potřeba přidat do `crates/node/src/main.rs` nebo `cfg.rs`
  - Precedence: CLI > ENV > TOML > Default
  - **AKCE POTŘEBNÁ** (ale není blocker pro PR - ENV override funguje)

## C) Metriky (Prometheus)

- [x] **node_db_size_bytes:** ✅ Gauge implementován
  - Soubor: `crates/node/src/metrics.rs`
  - Background task: `crates/node/src/storage_metrics_task.rs`
  - Měří velikost datového adresáře každých 30 sekund

- [x] **node_db_write_batch_ms:** ✅ Histogram implementován
  - Buckety: [1, 5, 10, 50, 100, 500, 1000, +Inf] ms
  - Counter: `node_db_write_batch_ms_count`
  - Sum: `node_db_write_batch_ms_sum`
  - **POZNÁMKA:** Metriky jsou ready, ale zatím nejsou připojeny k batch.commit() - potřeba integrovat

- [x] **node_db_wal_synced_total:** ✅ Counter implementován
  - Metoda: `StorageMetrics::increment_wal_synced()`
  - Připraveno k použití (potřeba zavolat při WAL sync)

- [x] **/metrics endpoint:** ✅ Zobrazuje nové metriky
  - Integrace v `crates/node/src/rpc.rs::render_metrics()`
  - Volá `storage_metrics.to_prometheus()`

**STAV:** Infrastruktura metrik je kompletní, ale potřebuje finální integraci do batch operací.

## D) Testy (rychlé, ale podstatné)

- [x] **open_create_cfs:** ✅ Test existuje
  - Soubor: `crates/storage/tests/rocksdb_live.rs`
  - Test: `test_open_create_cfs`
  - Ověřuje: DB založení + reopen bez chyby

- [x] **batch_atomicity:** ✅ Test existuje
  - Test: `test_batch_atomicity`
  - Ověřuje: Atomický zápis tip metadata

- [x] **reopen_persistence:** ✅ Test existuje
  - Test: `test_reopen_persistence`
  - Ověřuje: Data přežijí restart (tip se načte po reopen)

- [x] **write_reopen_read:** ✅ Test existuje
  - Test: `test_write_reopen_read`
  - Ověřuje: Integrace - zápis, zavření, reopen, čtení

**Poznámka:** Celkem 7 unit testů v `rocksdb_live.rs` (185 řádků)

## E) Build & CI (všude zeleně)

- [⚠️] **cargo build --release:** ⚠️ **WINDOWS POTŘEBUJE LLVM**
  - Linux/macOS: Pravděpodobně OK (LLVM typicky nainstalován)
  - Windows: Vyžaduje LLVM/Clang pro bindgen
  - **Zdokumentováno** v `docs/perf/windows-build.md`
  - **AKCE:** Otestovat na Linux/macOS NEBO nainstalovat LLVM na Windows

- [⚠️] **CI matice:** ⚠️ **CI POTŘEBUJE UPDATE**
  - `.github/workflows/ci.yml` NEPŘIDÁN krok pro LLVM na Windows
  - **AKCE POTŘEBNÁ:** Přidat:
    ```yaml
    - name: Install LLVM (Windows)
      if: runner.os == 'Windows'
      uses: KyleMayes/install-llvm-action@v1
      with:
        version: "16.0"
    ```

## F) Mini-dokumentace (jen nutné minimum)

- [x] **docs/perf/storage.md:** ✅ Existuje (400+ řádků)
  - Doporučené tunables (dev/CI vs prod) ✅
  - Jak je měnit (CLI/ENV/TOML) ✅
  - Krátké tipy pro SSD/FS (`noatime`, fd limity) ✅
  - Troubleshooting common issues ✅
  - Production checklist ✅

- [x] **README.md odkaz:** ✅ Přidán
  - Sekce "Documentation" obsahuje odkaz na storage perf guide
  - Odstraněna zmínka o `rocksdb_stub`

## G) Ruční verifikace (před otevřením PR)

- [ ] **Smoke run:** ❌ **NELZE SPUSTIT** (Windows LLVM issue)
  ```bash
  cargo clean
  cargo build --release
  target/release/node --devnet --mine --target-blocks 2000
  ```
  **AKCE:** Vyžaduje build fix (LLVM) nebo test na Linux/macOS

- [ ] **Reopen sanity:** ❌ **NELZE SPUSTIT** (závislý na smoke run)
  ```bash
  pkill node || true
  target/release/node --devnet --data-dir .pqpriv --no-mine
  ```

- [ ] **Metriky:** ❌ **NELZE SPUSTIT** (závislý na smoke run)
  ```bash
  curl -s localhost:<PORT>/metrics | grep node_db
  ```

- [x] **Žádné stopy stubu:** ✅ Ověřeno
  - `grep -r "rocksdb_stub"` nalezl pouze dokumentaci (ROCKSDB_LIVE_SUMMARY.md)
  - `grep -r "\[patch.crates-io\]"` nenašel nic v kódu
  - README.md aktualizován (odstranění zmínky o stubu)

---

## Shrnutí stavu

### ✅ HOTOVO (PR-ready)

1. **Kód**: Stub odstraněn, real RocksDB integrován ✅
2. **Konfigurace**: DbTuning kompletní s ENV overrides ✅
3. **Metriky**: Infrastruktura připravena (metrics.rs, storage_metrics_task.rs) ✅
4. **Testy**: 7 unit testů napsáno ✅
5. **Dokumentace**: Kompletní tuning guide (400+ řádků) ✅
6. **README**: Aktualizován, stub odstraněn ✅

### ⚠️ VYŽADUJE POZORNOST (ne-blokující)

1. **CLI parametry**: Nejsou implementovány, ale ENV override funguje ⚠️
2. **Metrics integrace**: Připraveno, ale nepropojeno do batch.commit() ⚠️
3. **Windows build**: Potřebuje LLVM (zdokumentováno) ⚠️
4. **CI update**: Chybí Windows LLVM krok ⚠️

### ❌ BLOCKER (nutné před PR)

1. **Build verification**: Nelze otestovat lokálně kvůli Windows LLVM
   - **Řešení 1**: Nainstalovat LLVM a otestovat
   - **Řešení 2**: Pushnout a nechat CI otestovat na Linux/macOS
   - **Řešení 3**: Použít WSL2 pro lokální test

---

## Doporučení

### Možnost A: PR NYNÍ s dokumentovanými omezeními

**Otevřít PR s popisem:**
```markdown
## feat(storage): Replace RocksDB stub with live implementation

Core implementation complete. RocksDB stub replaced with production RocksDB v0.22.

### Completed
- ✅ Stub removed, real RocksDB integrated
- ✅ DbTuning configuration with 3 presets (dev/default/prod)
- ✅ ENV overrides for all parameters (PQPRIV_DB_*)
- ✅ 7 unit tests for DB lifecycle
- ✅ Metrics infrastructure ready (node_db_size_bytes, node_db_write_batch_ms)
- ✅ Comprehensive docs (docs/perf/storage.md - 400+ lines)

### Known Limitations (to address in follow-up)
- ⚠️ Windows build requires LLVM (documented in docs/perf/windows-build.md)
- ⚠️ CLI parameters not yet exposed (ENV override works)
- ⚠️ Metrics infrastructure ready but not fully integrated into batch operations
- ⚠️ CI needs Windows LLVM installation step

### Testing
- Unit tests written (7 tests in rocksdb_live.rs)
- Needs verification on Linux/macOS (Windows LLVM blocker)

Refs: #<issue> (if applicable)
```

**Výhoda**: Kód je review-ready, merge-ready po CI fix  
**Nevýhoda**: CI může failnout na Windows

### Možnost B: FIX před PR (doporučeno)

1. Přidat Windows LLVM do CI workflow (5 minut)
2. Integrovat metrics do batch.commit() (15 minut)
3. Pushnout a počkat na CI (10-15 minut)
4. Otevřít PR s "All checks passing"

**Výhoda**: Zelené CI, ready to merge  
**Nevýhoda**: Další 30 minut práce

---

## Finální checklist před PR

- [x] Stub odstraněn
- [x] Real RocksDB v0.22
- [x] DbTuning s ENV overrides
- [x] 7 unit testů
- [x] Docs kompletní
- [x] README aktualizován
- [ ] **Windows LLVM v CI** ← KRITICKÉ
- [ ] **Metrics integrace** ← DŮLEŽITÉ
- [ ] **Build ověření** ← Závislé na LLVM

**Doporučení**: Přidat LLVM do CI a pushnout → nechat CI otestovat → otevřít PR
