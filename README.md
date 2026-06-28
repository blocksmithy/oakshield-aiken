# oakshield-aiken

Aiken primitives for verifying zero-knowledge and Merkle proofs on Cardano
(Plutus V3, BLS12-381).

> [!WARNING]
> **v0.2 — unaudited. Testnet only.**
>
> This library is pre-audit and has not been reviewed by any third party.
> Do not use it to secure mainnet funds. Suitable for testnet experimentation,
> design exploration, and review.

The primary use case proves **Cardano transaction inclusion**: that a
transaction belongs to the set certified by Mithril. The validator verifies a
RISC0 proof on-chain and binds it to a certified root read from a tip registry,
rather than recomputing the Mithril Merkle path on Cardano (see
[Why a proof, not a Merkle walk](#why-a-proof-not-a-merkle-walk)).

The verifier targets native `risc0-groth16-bls` proofs: a RISC0 STARK proved
directly over BLS12-381, with five native field-element public inputs.

## Install

```toml
# aiken.toml
[[dependencies]]
name = "blocksmithy/oakshield-aiken"
version = "0.2.1"
source = "github"
```

## Layout

The on-chain library is `lib/` (these are the modules you import); each is
demonstrated by an example in `validators/`. `lib/dev/` is test support (the
production proof vectors and test builders), and `sdk/` is the off-chain Rust
codec. Tests live under `lib/tests/` and `validators/tests/`.

```
ON-CHAIN MODULES (lib/)
  crypto/groth16.ak      Groth16 verifier over BLS12-381 (gnark outer, loop path, BSB22)
  crypto/risc0.ak        RISC0 receipt → public inputs + verify_receipt (one-call)
  crypto/hash_to_field.ak  RFC 9380 expand_message_xmd for gnark's BSB22 commitment
  wire.ak                Decode vk/proof/public.cardano.bin on-chain
  mithril/journal.ak     Decode oakshield chain-proof / tx-inclusion journals
  mithril/tip.ak         Tip-registry datum + read_tip / read_certified_root
  mithril/tx_inclusion.ak  Verify tx inclusion + consume (nullify) committed txs
  mithril/tx_inclusion_sha256.ak
                         SHA-256 IMT (depth 40) inclusion verifier for the
                         oaks_txtree proof variant (cheap on-chain path,
                         amortises the SNARK across many inclusion calls)
  cardano/registry.ak    Identity-NFT reference-input lookup
  cardano/authority.ak   Withdraw-zero governance authority check
  cardano/state_thread.ak  Continuing state-thread output + datum
  cardano/nullifier.ak   Spend-once / replay protection (MPF) + derive
  cardano/nullifier_shard.ak  Sharded nullifier sets for parallel spends
  merkle/simple.ak       Generic binary Merkle inclusion, pluggable blake2b / sha2-256

EXAMPLE VALIDATORS (validators/)
  groth16_verify · identity_bls_verify · wire_verify
  tx_inclusion · txtree_inclusion · tx_inclusion_nullifier
  nullifier_spend · sharded_nullifier · merkle_gate · authority_gate

OFF-CHAIN          sdk/        Rust codec for the wire format
TESTS              lib/tests/ + validators/tests/
TEST SUPPORT       lib/dev/    ceremony proof vectors + testkit (not part of the on-chain API)
```

## Proof artifacts

The proof, verification key, and journal come from the **`risc0-groth16-bls`**
prover — a RISC0 STARK proved directly over BLS12-381, a separate project. It
emits four files in the Cardano wire format:

- `vk.cardano.bin` — verification key (pin its `sha256` on-chain).
- `proof.cardano.bin` — the Groth16 proof.
- `public.cardano.bin` — the public inputs (also re-derivable from the journal).
- `journal` — the guest's committed output bytes.

Two journal shapes are decoded on-chain: `oaks_comp` (a chain/tip proof) and
`oaks_tx` (a tx-inclusion proof). The `oaks_txtree` variant is different — it
publishes a SHA-256 tree root `Y` that cheap inclusion proofs verify against,
rather than a journal decoded on-chain. Parse the files off-chain with
[`sdk/`](sdk/), or carry the raw `proof`/`journal` bytes in the redeemer and
parse on-chain with [`lib/wire.ak`](lib/wire.ak). A ready-to-copy real
VK/proof/journal lives in [`lib/dev/ceremony.ak`](lib/dev/ceremony.ak).

## Usage

Verify a RISC0-STARK-wrapped-in-Groth16 proof. `journal`/`params`/`proof`/`vk`
come from your redeemer and validator parameters:

```aiken
use crypto/groth16
use crypto/risc0

let public = risc0.lift_to_scalars(journal, params)   // 5 native BLS12-381 Fr inputs
let ok = groth16.verify(proof, public, vk)
// …or in one call: risc0.verify_receipt(vk, params, proof, journal)
```

Prove a transaction is in the Mithril-certified set, binding to a tip registry.
Inside a spend handler, `self` is the `Transaction`:

```aiken
use mithril/tip            // module qualifier for read_certified_root
use mithril/tip.{FromTip}  // the RootSource constructor
use mithril/tx_inclusion

// tip_name is your deployment's current-tip NFT asset name — your choice.
let root = tip.read_certified_root(self, registry_policy, tip_name, FromTip)
let ok = tx_inclusion.verify_inclusion(proof, journal, vk, params, root, tx_id)
```

Enforce a proof/secret is used at most once (replay protection). The set is one
32-byte root in a datum; `spend` takes the current root and returns the new one,
aborting on reuse:

```aiken
use cardano/nullifier

// datum_root is the current set root (use nullifier.empty_root for a fresh set)
let new_root = nullifier.spend(datum_root, the_nullifier, proof)  // aborts if already spent
// put new_root in the continuing output's datum
```

The `nullifier` must be bound into the verified statement (a Groth16 public
input / journal field), not freely chosen — otherwise the set is bypassable.

## Examples

Complete, compiling validators are in [`validators/`](validators/) — read these
as the canonical end-to-end usage:

- [`groth16_verify.ak`](validators/groth16_verify.ak) — unlock on a valid Groth16 proof.
- [`identity_bls_verify.ak`](validators/identity_bls_verify.ak) — **full** verification of a real production STARK→SNARK proof (the `small-ceremony-2026-06` fixture): verifies the proof *and* binds the public inputs to the committed journal via [`risc0.verify_receipt`](lib/crypto/risc0.ak). Round-tripped in [`lib/tests/dev/ceremony.test.ak`](lib/tests/dev/ceremony.test.ak) (accept the production proof, reject a tampered one, match the pinned VK hash).
- [`wire_verify.ak`](validators/wire_verify.ak) — verify a receipt straight from the raw `proof.cardano.bin` wire bytes in the redeemer.
- [`tx_inclusion.ak`](validators/tx_inclusion.ak) — path A: tx inclusion against a registry root.
- [`txtree_inclusion.ak`](validators/txtree_inclusion.ak) — path B: cheap SHA-256 inclusion against a pinned tree root `Y` (the `oaks_txtree` variant), amortising one SNARK across many checks.
- [`nullifier_spend.ak`](validators/nullifier_spend.ak) — spend-once gating with a nullifier set.
- [`tx_inclusion_nullifier.ak`](validators/tx_inclusion_nullifier.ak) — tx inclusion with per-`tx_id` replay protection: a proof carrying several tx_ids can be consumed in one transaction or split across several, and each tx_id is nullified at most once.

Each has a test under [`validators/tests/`](validators/tests/) showing how to
construct inputs and exercise the handler (against the real production proof in
[`lib/dev/ceremony.ak`](lib/dev/ceremony.ak)).

Browse the full API: `aiken docs` (writes `./docs`).

## Off-chain (Rust)

[`sdk/`](sdk/) is a dependency-free Rust crate that parses and serializes the
prover's wire files — the byte-exact inverse of [`lib/wire.ak`](lib/wire.ak):

```rust
use oakshield_sdk::{VerificationKey, Proof, PublicInputs};
let vk = VerificationKey::parse(&vk_bytes)?;
let proof = Proof::parse(&proof_bytes)?;
```

Because `wire.ak` parses on-chain too, a validator's redeemer can carry the raw
proof bytes + journal ([`Redeemer`](sdk/src/lib.rs)) — no PlutusData encoding of
the proof itself. You still wrap the two byte fields in a redeemer
`Constr(0, [proof_wire, journal])` (see the `Redeemer` doc). Round-tripped
against the production fixtures in `sdk/tests/`.

## Failure modes

For a verifier it matters whether a check **aborts** the script or **returns
`False`**:

- `groth16.verify` / `risc0.verify_receipt` / `tx_inclusion` **abort** (script fails) on
  malformed input — wrong byte lengths, non-canonical scalars, off-curve or
  small-subgroup points, point-at-infinity, an out-of-range header, or a root
  that does not match the reference input.
- They **return `False`** only when the inputs are well-formed but the proof
  does not satisfy the equations (a genuine "this proof is invalid").

Either way the spending transaction is rejected; the distinction is for
debugging. When a `verify` aborts, the failing `expect` expression appears in
the trace.

## Why a proof, not a Merkle walk

Mithril certifies the transaction set as a **Blake2s-256 Merkle Mountain Range**
root. The intuitive design — read that root from chain and verify a Merkle
inclusion proof directly in Aiken — is not viable on mainnet:

- Plutus V3 has no Blake2s builtin. Implemented from the integer and CIP-0122
  bitwise builtins, one 64-byte Blake2s compression costs ≈ **2.37 B CPU /
  3.57 M mem** (measured).
- A real mainnet inclusion proof needs ≈ **30 compressions** (the certified
  tree spans millions of positions), i.e. ≈ 71 B CPU / 107 M mem — about **7×
  over** Cardano's per-tx limits of 10 B CPU / 14 M mem. The memory ceiling is
  a hard wall that cannot be split within one transaction.

So the Merkle walk is performed inside the RISC0 guest (where it is cheap) and
the on-chain validator verifies the resulting proof — a BLS pairing that fits
the budget. Trust is unchanged: a sound proof attests the Merkle check was done
correctly, exactly as the tip's own root was already placed on-chain by proof.

## Measurements

Plutus V3, against the real production proof in [`lib/dev/ceremony.ak`](lib/dev/ceremony.ak)
(`small-ceremony-2026-06`, native `risc0-groth16-bls`). Per-tx limits: 10 B CPU, 14 M mem.

| Operation | CPU | Mem |
|---|---|---|
| `groth16.verify` (production proof, 5 native publics) | 4.54 B | 0.35 M |
| `risc0.verify_receipt` (lift + verify, one call) | 4.56 B | 0.40 M |
| `risc0.lift_to_scalars` | ~1 M | ~10 K |
| `tip.read_certified_root` (reference input) | 31 M | 101 K |
| `journal.decode_tx_inclusion` + membership | ~12 M | ~38 K |

A `tx_inclusion` spend is dominated by the pairing (~4.5 B CPU), comfortably
within budget. The MSM over the 5 `ic` points is ~1 B of that; a future native
BLS MSM builtin (CIP-133, van Rossem) would cut it further.

## Security notes

- **Root binding is load-bearing.** `tx_inclusion.verify_inclusion` requires the
  proof's committed `tx_merkle_root` to equal a root you trust (a registry
  reference input). Without it, a valid proof over an attacker's own root would
  pass.
- **VK / RISC0 parameters pin the prover.** `image_id`, `control_root`, and
  `control_id_fr` bind a specific guest and prover release; supply them as
  validator parameters or a trusted reference datum, never from the redeemer.
- **Point decompression enforces subgroup membership** via the CIP-0381
  builtins; off-curve or small-subgroup bytes are rejected at decompression.
- **Leaf-format / proof-version (`oaks_tx` v1 vs v2)** must match the network the
  certified root came from.
- Not audited. Do not deploy to mainnet.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
