# Windows Build Requirements for RocksDB

## Issue

Building RocksDB on Windows requires LLVM/Clang for bindgen to generate FFI bindings.

## Solutions

### Option 1: Install LLVM (Recommended for Development)

1. Download LLVM from https://github.com/llvm/llvm-project/releases
2. Install LLVM (ensure "Add LLVM to PATH" is checked)
3. Set environment variable:
   ```powershell
   $env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
   ```
4. Build again:
   ```powershell
   cargo build --package storage
   ```

### Option 2: Use Pre-compiled RocksDB (Easier for CI)

Add to `Cargo.toml`:
```toml
[dependencies]
rocksdb = { version = "0.22", default-features = false, features = ["lz4", "zstd", "multi-threaded-cf", "static"] }
```

The `static` feature may provide pre-built libraries for Windows, avoiding the need for LLVM.

### Option 3: WSL2 (For Development)

Use Windows Subsystem for Linux:
```bash
wsl
cd /mnt/c/Users/.../pq-priv
cargo build --package storage
```

## GitHub Actions CI

For CI, we should install LLVM in the workflow:

```yaml
- name: Install LLVM (Windows)
  if: runner.os == 'Windows'
  run: |
    choco install llvm -y
    echo "LIBCLANG_PATH=C:\Program Files\LLVM\bin" >> $GITHUB_ENV
```

## Verification

After setup, verify:
```powershell
clang --version
cargo build --package storage
```
