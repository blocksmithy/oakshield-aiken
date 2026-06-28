# Changelog

## 0.2.1

Fix: the `mithril/tip` reader no longer dictates the current-tip NFT's asset
name. A library must not force its naming onto a deployment; the name is now a
caller parameter, matching how `set_name` / `y_name` are already parameterized.

This changes the `read_tip` / `read_certified_root` signatures and the two
tip-consuming validators' parameters — update callsites (see Migration).

### Migration

- `read_tip(self, policy, source)` → `read_tip(self, policy, tip_name, source)`
  (same for `read_certified_root`); pass your deployment's current-tip NFT name.
  `FromHistory` is unaffected (it keys on `tip_hash`).
- `validators/tx_inclusion` and `validators/tx_inclusion_nullifier` gain a
  `tip_name: AssetName` parameter, after `registry_policy`. A deployment that
  relied on the old hardcoded `"singleton"` passes it explicitly, or picks a
  clearer name. The `singleton_name` constant was removed.

## 0.2.0

Refocused the library on native `risc0-groth16-bls` proofs (five BLS12-381
field-element public inputs); the emulated-BN254 `bls-snark` path (20 limbs) was
removed. Also a script-size pass on `mithril/tx_inclusion_sha256` and
`cardano/nullifier` — removing sum-type / opaque-wrapper overhead — so downstream
validators compile well under Cardano's 16 KB per-validator cap.

Breaking changes (from 0.1.0):

- `crypto/risc0` — removed `lift_to_limbs`, `decompose_to_limbs`, `r_bn254`,
  `limb_modulus`, and `validate_params_shape`. Use `lift_to_scalars` or
  `verify_receipt`; `control_id_fr` is now a BLS12-381 Fr.
- `crypto/groth16` — `VerificationKey` no longer carries the `committed` field;
  the BSB22 challenge is `HashToField(commitment.uncompressed)`. The native
  circuit commits no public wire (gnark `PublicAndCommitmentCommitted = [[]]`).
  `wire.parse_vk` asserts every committed count is 0 and `validate_vk_shape`
  asserts `n_commitments == 1`, so a VK with a different commitment shape is
  rejected on parse rather than mis-verified.
- `wire.parse_public` asserts `n_limbs == 1`.
- Removed the `risc0_verify` example; `identity_bls_verify` and `wire_verify`
  cover native receipt verification.
- `mithril/tx_inclusion_sha256` — raw-sibling API: dropped `ProofVersion`,
  `Sibling`, and `InclusionProof`; v1/v2 dispatch is implicit in `block_le8`
  length; callers pass 40 raw `ByteArray` siblings (off-chain expanders substitute
  `zeros[k]`); added a 32-byte sibling-length pin. New signature:
  `verify_inclusion(y_root, txid, block_le8, slot_le8, leaf_index, siblings)`. The
  `0x00`/`0x01`/`0x03` domain-separation prefixes and the `zeros` table are kept.
- `cardano/nullifier` — minimal `ByteArray` API: `derive`, `spend(old_root,
  nullifier, proof) -> ByteArray`, and the `empty_root` constant. Removed
  `NullifierSet`, `empty`, `from_root`, `root`, `is_spent`, `is_unspent`; compose
  with `aiken/merkle_patricia_forestry` directly for membership queries.
- `mithril/tx_inclusion.verify_and_consume` / `consume_inclusions_unchecked` —
  the set parameter and return type are now `ByteArray` (the root).

Native on-chain Groth16 verification costs 4.54 B CPU / 0.35 M mem (per-tx limits
10 B / 14 M); a SHA-256 inclusion check is ~0.5 B CPU / 1.7 M mem.

## 0.1.0

Initial release.

Proof verification:

- `crypto/groth16` — Groth16 verifier over BLS12-381 (gnark outer verifier, loop
  path, single BSB22 commitment) with verification-key shape validation.
- `crypto/risc0` — RISC0 `ReceiptClaim` digest chain and native public-input
  derivation (`lift_to_scalars`, `verify_receipt`).
- `crypto/hash_to_field` — RFC 9380 `expand_message_xmd` over SHA-256 for the
  BSB22 commitment challenge (pinned to gnark v0.15.0).
- `wire` — on-chain decoders for `vk`/`proof`/`public.cardano.bin`, so a redeemer
  can carry the raw proof bytes; round-tripped by the `sdk/` codec.

Mithril:

- `mithril/journal` — decoders for the chain-proof (`oaks_comp`) and tx-inclusion
  (`oaks_tx`) journals, with transaction membership.
- `mithril/tip` — tip-registry datum schema and certified-root readers.
- `mithril/tx_inclusion` — verify Cardano transaction inclusion against a
  certified root, and nullify committed transactions keyed by `tx_id`.
- `mithril/tx_inclusion_sha256` — SHA-256 incremental Merkle tree (depth 40)
  inclusion verifier for the `oaks_txtree` variant: the SNARK is verified once and
  amortised across many cheap SHA-256 inclusion checks.

Cardano:

- `cardano/registry`, `cardano/authority` — identity-NFT reference-input lookup
  and withdraw-zero authority check.
- `cardano/state_thread` — continuing state-thread output and datum.
- `cardano/nullifier`, `cardano/nullifier_shard` — spend-once / replay protection
  via a Merkle-Patricia Forestry set, with hash-prefix sharding for parallel spends.
- `merkle/simple` — generic binary Merkle inclusion with a pluggable hash, and
  domain-separated leaves and internal nodes.

Off-chain:

- `sdk/` — a dependency-free Rust crate that parses and serializes the wire
  format, the byte-exact inverse of `wire.ak`.

On-chain verification of the Mithril Blake2s Merkle Mountain Range is not
provided: at mainnet scale its cost exceeds Cardano's per-transaction limits (see
the README). Inclusion is proven inside the RISC0 guest and the proof verified
on-chain.
