//// Nullifier set — spend-once / replay protection.
////
//// An authenticated set of "already used" tags, backed by a
//// Merkle-Patricia Forestry (MPF) accumulator. MPF hashes with
//// `blake2b_256` — a Plutus builtin — so membership and insertion
//// are cheap on-chain, and the whole set is represented on-chain by
//// a single 32-byte root stored in a datum.
////
//// To gate a one-time action: prove the nullifier is **unspent**
//// (via the `spend` call's internal exclusion proof), then produce
//// the new root with it inserted (the returned bytes go in the
//// continuing output's datum). A second attempt with the same
//// nullifier fails, because [spend](#spend) aborts when the
//// nullifier is already present.
////
//// **SECURITY**: the nullifier MUST be bound into the verified
//// statement — a Groth16 public input or a journal field,
//// deterministically derived from the secret. A nullifier the
//// spender can choose freely defeats the set (they would just pick
//// a fresh one each time).
////
//// **Minimal API.** The on-chain validator pattern needs only `spend`
//// (the insert-with-non-membership-proof transition) and `derive` (the
//// domain-separated nullifier derivation), plus the `empty_root`
//// constant. Validators pass the 32-byte root directly as `ByteArray`;
//// for membership queries, compose with `aiken/merkle_patricia_forestry`
//// directly.

use aiken/builtin
use aiken/merkle_patricia_forestry as mpf
use aiken/primitive/bytearray

/// An MPF (non-)membership proof, produced off-chain.
pub type Proof =
  mpf.Proof

/// The root of an empty nullifier set (no nullifiers spent yet) — the MPF
/// empty-trie root. A fresh deployment initialises its set-root datum to this.
pub const empty_root: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

// Set semantics: each nullifier key maps to a fixed, empty value.
const marker: ByteArray = #""

/// Derive a domain-separated nullifier from a proof-bound value:
/// `blake2b_256(domain ‖ committed)`. `committed` MUST be a value
/// the proof commits to (a public input or journal field), never a
/// free redeemer field, so the spender cannot mint a fresh nullifier
/// for the same action. `domain` separates nullifiers of different
/// purposes that share a value.
///
/// The concatenation is unprefixed, so `domain` must be a
/// fixed-length constant (otherwise `domain ‖ committed` could
/// collide across purposes).
pub fn derive(domain: ByteArray, committed: ByteArray) -> ByteArray {
  builtin.blake2b_256(bytearray.concat(domain, committed))
}

/// Insert `nullifier` into the set rooted at `old_root` and return
/// the new root. **Aborts** if the nullifier is already present
/// (replay) — the `proof` MUST be a valid MPF proof of EXCLUSION at
/// the time of call. The internal MPF `insert` first asserts
/// `excluding(nullifier, proof) == old_root` (the non-membership
/// check that prevents replay), then computes the new root via
/// `including(nullifier, marker, proof)`.
///
/// The returned bytes must appear in the continuing nullifier-set
/// UTxO's datum — the validator asserts byte equality.
pub fn spend(
  old_root: ByteArray,
  nullifier: ByteArray,
  proof: Proof,
) -> ByteArray {
  mpf.from_root(old_root)
    |> mpf.insert(nullifier, marker, proof)
    |> mpf.root
}
