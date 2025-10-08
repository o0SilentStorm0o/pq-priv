# Contributing to PQ-PRIV

Děkujeme, že chcete pomoci s implementací post-kvantové soukromé sítě PQ-PRIV. Tento dokument shrnuje minimální požadavky na vývojové prostředí, proces review a zásady bezpečnosti.

## Požadovaný toolchain a MSRV

* **MSRV (minimální podporovaná verze Rustu):** `1.90.0`.
* Toolchain je uzamčen v souboru [`rust-toolchain.toml`](./rust-toolchain.toml). Prosíme, neměňte jej bez koordinace s jádrovým týmem.
* Pokud je potřeba verzi navýšit:
  1. Otevřete RFC/issue se zdůvodněním (bezpečnostní fix, potřeba 2024 edition apod.).
  2. Aktualizujte `RUST_TOOLCHAIN.txt`, `rust-toolchain.toml`, CI workflow a dokumentaci.
  3. Ověřte, že `cargo build --locked` a `cargo test --locked` prochází na starém i novém toolchainu.
  4. Informujte komunitu v release poznámkách.

## Lokální vývoj

```bash
# instalace komponent
rustup toolchain install 1.90.0
rustup component add clippy rustfmt

# kompletní sada kontrol
make fmt
make lint
make test
make audit
```

* Pokud ještě nemáte `cargo-deny` a `cargo-audit`, nainstalujte je pomocí `cargo install cargo-deny cargo-audit`.
* Všechny příkazy používejte s přepínačem `--locked`, aby build zůstal deterministický.
* V kritických cestách (kryptografie, konsensus) se vyhýbejte `unwrap()`/`expect()` – raději propagujte chyby.
* Dodržujte strukturu workspace dle blueprintu a dbejte na `alg_tag` krypto-agilitu.

## Povinné kontrolní kroky (Required checks)

Všechny pull requesty musí v CI projít následujícími kroky. Před odevzdáním PR spusťte ekvivalentní příkazy lokálně:

* `cargo fmt --all -- --check`
* `cargo clippy --workspace --all-targets --all-features -- -D warnings`
* `cargo test --workspace --all-targets --locked`
* `cargo deny check`
* `cargo audit --deny warnings`

Tyto kontroly jsou nastavené jako „required“ pro merge do chráněných větví.

## Reprodukovatelné buildy

* Release kompilace spouštějte přes `make build-release`, které nastaví konzistentní `RUSTFLAGS` a profil `release` (`codegen-units=1`, `thin LTO`, `strip` symbolů).
* Pro auditovatelnost ukládejte artefakty a kontrolní součty (`SHA256SUMS`).
* Docker image lze vytvořit pomocí `make docker-build`; multi-stage Dockerfile minimalizuje runtime image.

## Git workflow

1. Vytvořte feature větev z `main`/`work`.
2. Commity pište srozumitelně (`component: stručný popis`).
3. Každá změna musí obsahovat:
   * implementaci + testy,
   * aktualizovanou dokumentaci (`/spec`, README, ADR),
   * záznam v `CHANGELOG.md` (pokud mění chování).
4. Otevřete PR s vyplněnou šablonou a přiloženými výstupy z testů.

## Testování a bezpečnost

* `cargo test --workspace --all-targets --locked`
* `cargo clippy --workspace --all-targets --all-features -- -D warnings`
* `cargo deny check` + `cargo audit --deny warnings`
* V případě bezpečnostního incidentu postupujte dle [SECURITY.md](./SECURITY.md).

## Dokumentace

* Specifikace udržujte v adresáři [`spec/`](./spec/README.md). Každý zásadní protokolový update doprovázejte ADR (`docs/ADR-XXXX.md`).
* Release proces popisuje [`spec/build.md`](./spec/build.md).

## Komunikace

* Technické diskuse: GitHub Issues + týdenní sync.
* Bezpečnostní reporty: viz [Security disclosures](https://pq-priv.example.com/security).

Děkujeme za dodržování standardů – bezpečnost a auditovatelnost mají nejvyšší prioritu.
