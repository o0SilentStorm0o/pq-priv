# Implementation Blueprint (v0.9) – Quick Reference

This document summarises the high-level implementation goals that guide the PQ-PRIV MVP. It mirrors the planning
blueprint shared with the engineering team and should be kept in sync with any governance-approved updates.

## Core Pillars
- Post-quantum security first (Dilithium primary signatures, SPHINCS+ fallback, STARK proofs for privacy).
- Privacy-by-default UTXO model with stealth addresses, hidden amounts, and one-of-many spends.
- Operational readiness through audit tooling, exchange integrations, and light-client friendly storage.

## Sprint Overview
Refer to [Appendix A in the blueprint prompt](../README.md) for the living backlog summary. Each sprint described
there has a matching engineering prompt in `/spec` once implementation artifacts exist.

## Keeping it Updated
When roadmap decisions change, update this file with:
1. New cryptographic primitives or parameter selections.
2. Adjusted sprint scopes or acceptance criteria.
3. Links to new specification chapters (range proofs, governance, SDK, etc.).

> _Source_: Internal PQ-PRIV blueprint v0.9. For the canonical text, consult the internal governance repository or the
shared product brief circulated with the core team.
