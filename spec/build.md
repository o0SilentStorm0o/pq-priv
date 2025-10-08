# Build & Release Handbook

Tento dokument popisuje postupy pro deterministické buildy, CI pipelines a publikaci binárních artefaktů PQ-PRIV. Navazuje na implementační blueprint a je závazný pro všechny oficiální releasy.

## Toolchain

* **Rust**: 1.90.0 (edition 2024). Toolchain je uzamčen v `rust-toolchain.toml`.
* **Cargo**: používejte `--locked`, aby se respektoval `Cargo.lock`.
* **C compilers / linkers**: Docker image instaluje `clang`, `pkg-config`, `libssl-dev`.

## Reprodukovatelné buildy

1. Vyčistěte předchozí výstupy: `rm -rf target/ dist/`.
2. Spusťte `make build-release`. Makefile nastavuje `codegen-units=1`, `thin LTO`, `strip` symbolů a `-C link-arg=-s`.
3. Výsledné binárky `target/release/node` a `target/release/wallet` zkopírujte do `dist/` jako `pqprivd` a `pqpriv-wallet`.
4. Vygenerujte `SHA256SUMS`:

```bash
python scripts/write_sha256.py dist/
```

5. Podepište soubor `SHA256SUMS` pomocí release klíče (GPG/hardware HSM) a publikujte spolu s binárkami.

## CI pipelines

### `.github/workflows/ci.yml`

* Spouští se na push, pull request a manuálně.
* Matrix pro `ubuntu-latest`, `macos-latest`, `windows-latest`.
* Kroky: `cargo fmt --check`, `cargo clippy`, `cargo test`, `cargo deny`, `cargo audit`.
* Bezpečnostní kontroly (`deny`/`audit`) běží na linuxovém runneru.

### `.github/workflows/release.yml`

* Spouští se na tag `v*` nebo ručně.
* Vytváří artefakty pro linux/macos/windows, přejmenovává binárky na `pqprivd` a `pqpriv-wallet`.
* Zapisuje `SHA256SUMS` v rámci workflow a nahrává artefakty.

## Docker image

* `docker/Dockerfile` je multi-stage:
  * **builder**: `rust:1.90-bullseye`, instaluje build závislosti a kompiluje binárky.
  * **runtime**: `debian:bookworm-slim`, vytváří neprivilegovaného uživatele `pqpriv` a instaluje binárky.
* Lokální build: `make docker-build`.
* Spuštění testovací instance:

```bash
docker run --rm pqpriv:dev --help
```

## Testnet skripty

* `scripts/testnet-up.sh` spouští lokální mining smyčku (`node run --blocks N`).
* `scripts/testnet-down.sh` bezpečně ukončí běžící procesy `target/release/node`.

## Release checklist

1. Všechny testy a linty zelené (`make lint`, `make test`, `make audit`).
2. Aktualizované specifikace (`/spec`), changelog, ADR.
3. `make build-release` + `SHA256SUMS`.
4. Podepsané artefakty nahrané přes `release.yml`.
5. Publikovaný security advisory, pokud release obsahuje bezpečnostní fixy.

Dodržování tohoto postupu je nezbytné pro auditovatelný a bezpečný provoz sítě.
