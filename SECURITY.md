# Security Policy

## Supported Versions
Only the `main` branch is actively supported during pre-release.

## Reporting a Vulnerability
Please email **security@pq-priv.org** with:
- clear description and impact
- PoC/Repro steps
- affected commit/commit range

We prefer **private disclosure** first. We will acknowledge within **72 hours**.
If accepted, we aim to provide a fix or mitigation within **14 days**, depending on severity.

## Scope (MVP)
- `crates/crypto`, `crates/node`, `crates/wallet`, `crates/pow`, `crates/codec`, `crates/spec`
- build/CI configs

Out of scope (for now): third-party dependencies, OS/Kernel issues.

## Public Advisory
After a fix and coordinated release, we publish a short advisory (CVE if applicable).
Please do not perform DoS or spam tests on public infra.

