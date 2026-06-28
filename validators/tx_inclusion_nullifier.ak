//// Example: tx-inclusion with per-transaction replay protection.
////
//// The script guards a state-thread UTxO (marked by an NFT) whose datum is the
//// nullifier-set root. To act, the spender presents a verified `oaks_tx` proof
//// and a list of transactions to nullify. For each one the validator checks it
//// is committed in the proof's journal and inserts its `tx_id` into the set;
//// the continuing output must carry the updated root.
////
//// The nullifier is the `tx_id` — a journal field bound by the proof, so it is
//// not freely chosen (and is immune to proof malleability). Consequences:
//// - a proof carrying two tx_ids can be consumed in one transaction
////   (`consume = [tx1, tx2]`) or split across two (`[tx1]` then `[tx2]`);
//// - each `tx_id` can be nullified at most once, ever — a replay aborts.
////
//// Aborts on malformed input or a failed binding (bad byte lengths,
//// off-curve points, a missing tip reference input, a root mismatch, an
//// uncommitted or replayed `tx_id`); returns False only on a well-formed but
//// invalid proof.

use cardano/assets.{AssetName, PolicyId}
use cardano/nullifier
use cardano/state_thread
use cardano/transaction.{OutputReference, Transaction}
use crypto/groth16.{Proof, VerificationKey}
use crypto/risc0.{Risc0Params}
use mithril/tip.{RootSource}
use mithril/tip
use mithril/tx_inclusion.{Consume}
use mithril/tx_inclusion as inclusion

/// Datum of the nullifier-set UTxO: the MPF root of spent `tx_id`s.
pub type SetDatum {
  root: ByteArray,
}

pub type Redeemer {
  /// The `oaks_tx` Groth16 proof.
  proof: Proof,
  /// The proof's committed journal (decoded for membership + root binding).
  journal: ByteArray,
  /// Which certified root to bind against (current Tip or an archived one).
  source: RootSource,
  /// Transactions to nullify in this spend, each with its MPF insertion proof.
  consume: List<Consume>,
}

validator tx_inclusion_nullifier(
  vk: VerificationKey,
  params: Risc0Params,
  registry_policy: PolicyId,
  tip_name: AssetName,
  set_policy: PolicyId,
  set_name: AssetName,
) {
  spend(
    datum: Option<SetDatum>,
    redeemer: Redeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(SetDatum { root }) = datum
    let certified_root =
      tip.read_certified_root(self, registry_policy, tip_name, redeemer.source)

    // Verify the proof, bind its root, and nullify the requested txs (each must
    // be committed; each insert aborts on replay).
    let updated_root =
      inclusion.verify_and_consume(
        redeemer.proof,
        redeemer.journal,
        vk,
        params,
        certified_root,
        root,
        redeemer.consume,
      )

    // The continuing state-thread output must carry the new root.
    continuing_set_root(self, own_ref, set_policy, set_name) == updated_root
  }

  else(_) {
    fail
  }
}

/// The nullifier-set root declared by the continuing state-thread output: the
/// unique output at the spent UTxO's address carrying the `(set_policy,
/// set_name)` NFT. Fails if that output is missing, ambiguous, or carries the
/// wrong datum shape — so the set can't be forked or its root dropped.
pub fn continuing_set_root(
  self: Transaction,
  own_ref: OutputReference,
  set_policy: PolicyId,
  set_name: AssetName,
) -> ByteArray {
  expect SetDatum { root } =
    state_thread.continuing_datum(self, own_ref, set_policy, set_name)
  root
}
