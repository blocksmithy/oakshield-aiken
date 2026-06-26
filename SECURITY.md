# Security Policy

## Status

> **oakshield-aiken is v0.x, unaudited, and intended for testnet use only.**

This library has not been reviewed by any third party. Do not use it to secure
mainnet funds. It is suitable for testnet experimentation, design exploration,
and review.

## Supported versions

Only the latest `0.x` release receives fixes. Pre-1.0 releases carry no
backward-compatibility guarantee.

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a vulnerability

Report security issues **privately**. Do not open a public issue.

Use GitHub's private vulnerability reporting at
[Security → Report a vulnerability](https://github.com/blocksmithy/oakshield-aiken/security/advisories/new).

We aim to acknowledge a report within a few business days and will agree a fix
and disclosure timeline with you.

## Scope

In scope:

- The on-chain verifiers and decoders in `lib/` (`crypto/groth16`,
  `crypto/risc0`, `wire`, `mithril/*`, `cardano/*`, `merkle/simple`).
- The off-chain wire codec in `sdk/`.

Out of scope:

- The example validators in `validators/` (illustrative, not production contracts).
- The RISC0 guest, the `risc0-groth16-bls` prover, and the Mithril certification
  the verifier relies on (separate projects).

## Security model

Verifier soundness depends on the caller honoring the invariants documented under
[Security notes](README.md#security-notes) in the README. In particular:

- **Root binding** — `tx_inclusion.verify_inclusion` must bind the proof's
  committed root to a trusted on-chain root (a registry reference input).
- **Parameter pinning** — `image_id`, `control_root`, `control_id_fr`, and the
  verification key must come from validator parameters or a trusted datum, never
  the redeemer.
- **Nullifier binding** — a nullifier must be derived from a proof-bound value,
  not freely chosen.

A report that a documented invariant can be bypassed, or that a malformed input
is accepted where it should be rejected, is in scope and welcome.
