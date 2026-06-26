//// Verify Cardano transaction inclusion against a certified root.
////
//// This is the trust-preserving on-chain check that avoids running the
//// Mithril Merkle path (Blake2s) on-chain: instead of recomputing the
//// inclusion proof, the validator verifies a RISC0 `oaks_tx` proof that
//// performed that check off-chain, then binds the proof's committed
//// `tx_merkle_root` to a root it trusts (read from a tip registry).
////
//// The caller supplies `certified_root` — typically from
//// [mithril/tip.read_certified_root](./tip.html#read_certified_root) — so the
//// trust anchor is an on-chain reference input, not the proof itself.

use aiken/collection/list
use cardano/nullifier
use crypto/groth16.{Proof, VerificationKey}
use crypto/risc0.{Risc0Params}
use mithril/journal.{TxInclusion}
use mithril/journal

/// Verify that `tx_id` is among the transactions a RISC0 `oaks_tx` proof
/// attests are included under `certified_root`.
///
/// Steps: derive the public inputs from the journal, verify the Groth16
/// proof, then require that the journal's committed root equals
/// `certified_root` and that `tx_id` is one of the committed records. The
/// root binding is load-bearing — without it, a valid proof over an
/// attacker's own root would pass.
pub fn verify_inclusion(
  proof: Proof,
  journal_bytes: ByteArray,
  vk: VerificationKey,
  params: Risc0Params,
  certified_root: ByteArray,
  tx_id: ByteArray,
) -> Bool {
  let decoded = journal.decode_tx_inclusion(journal_bytes)
  // Cheap binding checks first; the pairing is the expensive step.
  expect decoded.tx_merkle_root == certified_root
  expect journal.tx_committed(journal_bytes, decoded, tx_id)
  // Native publics (n_limbs = 1) — matches the production STARK→SNARK wrap.
  let public = risc0.lift_to_scalars(journal_bytes, params)
  groth16.verify(proof, public, vk)
}

/// One transaction to nullify: a committed `tx_id` plus the MPF proof that
/// inserts it into the nullifier set (proof of its absence at the current root).
pub type Consume {
  tx_id: ByteArray,
  proof: nullifier.Proof,
}

/// **Prefer [verify_and_consume](#verify_and_consume).** This is the low-level,
/// unchecked half: it nullifies the requested `tx_id`s against `set` WITHOUT
/// verifying the `oaks_tx` proof or binding the journal to a trusted root.
///
/// > [!WARNING]
/// > Calling this on a journal you have not independently verified and
/// > root-bound lets a caller nullify arbitrary transactions. Only use it if you
/// > have already run `decode_tx_inclusion`, bound the root, and verified the
/// > proof yourself.
///
/// For each item it asserts `tx_id` is one of the journal's committed records,
/// then inserts it. `nullifier.spend` aborts on replay, so each `tx_id` is
/// nullified at most once whether the items are batched or spread across
/// transactions.
pub fn consume_inclusions_unchecked(
  journal_bytes: ByteArray,
  decoded: TxInclusion,
  set_root: ByteArray,
  items: List<Consume>,
) -> ByteArray {
  list.foldl(
    items,
    set_root,
    fn(item, acc_root) {
      expect journal.tx_committed(journal_bytes, decoded, item.tx_id)
      nullifier.spend(acc_root, item.tx_id, item.proof)
    },
  )
}

/// Verify an `oaks_tx` proof, bind its committed root to `certified_root`, then
/// nullify the requested committed transactions. Returns the updated set root,
/// which must appear in the continuing output's datum. Aborts on an invalid
/// proof, a root mismatch, an uncommitted `tx_id`, or a replayed `tx_id`.
pub fn verify_and_consume(
  proof: Proof,
  journal_bytes: ByteArray,
  vk: VerificationKey,
  params: Risc0Params,
  certified_root: ByteArray,
  set_root: ByteArray,
  items: List<Consume>,
) -> ByteArray {
  let decoded = journal.decode_tx_inclusion(journal_bytes)
  expect decoded.tx_merkle_root == certified_root
  expect groth16.verify(proof, risc0.lift_to_scalars(journal_bytes, params), vk)
  consume_inclusions_unchecked(journal_bytes, decoded, set_root, items)
}
