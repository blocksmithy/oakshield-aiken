//// Example: spend-once gating with a nullifier set.
////
//// The script holds a UTxO whose datum is the nullifier-set root. To act, the
//// spender presents a nullifier and an MPF proof of its absence; the validator
//// inserts it (which aborts on replay) and requires the continuing output to
//// carry the new root. A second spend with the same nullifier fails.
////
//// In a real design the `nullifier` MUST come from the verified statement (a
//// Groth16 public input / journal field), not be freely chosen in the redeemer.
//// Otherwise the spender picks a fresh nullifier each time. This example keeps
//// it in the redeemer to isolate the set mechanics; compose it with
//// `crypto/groth16` or `mithril/tx_inclusion` to bind it.

use aiken/collection/list
use cardano/nullifier.{Proof}
use cardano/transaction.{InlineDatum, OutputReference, Transaction, find_input}

pub type SetDatum {
  root: ByteArray,
}

pub type Redeemer {
  nullifier: ByteArray,
  proof: Proof,
}

validator nullifier_spend {
  spend(
    datum: Option<SetDatum>,
    redeemer: Redeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(SetDatum { root }) = datum
    let updated_root =
      nullifier.spend(root, redeemer.nullifier, redeemer.proof)

    // The continuing output must carry the new root. This single-UTxO example
    // matches it by address only; a contract with several UTxOs at one address
    // must mark the state with a unique NFT (see cardano/state_thread and
    // sharded_nullifier) so the set can't be forked.
    expect Some(own) = find_input(self.inputs, own_ref)
    expect [continuing] =
      list.filter(self.outputs, fn(o) { o.address == own.output.address })
    expect InlineDatum(d) = continuing.datum
    expect SetDatum { root: new_root } = d
    new_root == updated_root
  }

  else(_) {
    fail
  }
}
