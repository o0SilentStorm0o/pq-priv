// Build script for crypto crate - enforces security invariants at compile time
//
// This script runs during `cargo build` and can emit warnings/errors to prevent
// misconfigurations.

fn main() {
    // AUDITOR-PROOF CHECK: Warn if dev_stub_signing is enabled in release mode
    //
    // The dev_stub_signing feature includes Ed25519 (non-PQC) for development only.
    // It MUST NOT be used in production as it's vulnerable to quantum attacks.

    let dev_stub_enabled = std::env::var("CARGO_FEATURE_DEV_STUB_SIGNING").is_ok();
    let is_release = std::env::var("PROFILE").unwrap_or_default() == "release";

    if dev_stub_enabled && is_release {
        // This will cause a compile error in release mode if dev_stub_signing is enabled
        panic!(
            "\n\n\
            ========================================================================\n\
            ERROR: dev_stub_signing feature MUST NOT be enabled in release builds!\n\
            ========================================================================\n\
            \n\
            The 'dev_stub_signing' feature includes Ed25519, which is NOT quantum-resistant.\n\
            This feature exists only for development/testing and violates security requirements.\n\
            \n\
            To fix:\n\
            1. Remove 'dev_stub_signing' from your build command\n\
            2. Ensure Cargo.toml does NOT include it in default features\n\
            3. Use Dilithium2 for all production signatures\n\
            \n\
            If you need Ed25519 for testing, use: cargo build --features dev_stub_signing\n\
            (This only works in debug mode)\n\
            ========================================================================\n\
            "
        );
    }

    // Emit helpful warning in debug mode when dev_stub_signing is enabled
    if dev_stub_enabled && !is_release {
        println!("cargo:warning=⚠️  dev_stub_signing feature is ENABLED (development mode only)");
        println!("cargo:warning=   Ed25519 signatures are NOT quantum-resistant!");
        println!("cargo:warning=   This feature will cause a compile error in release builds.");
    }

    // Rerun if feature flags change
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEV_STUB_SIGNING");
}
