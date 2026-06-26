//// Example: one shard of a sharded nullifier set (parallel spends).
////
//// Deploy `shard_count` instances, one per `shard_index`. Each only accepts
//// nullifiers in its home shard ([cardano/nullifier_shard](../lib/cardano/nullifier_shard.html)),
//// so the shards are disjoint and a nullifier can be spent in exactly one of
//// them — global uniqueness with no cross-shard coordination. Combines
//// [cardano/nullifier](../lib/cardano/nullifier.html) and
//// [cardano/state_thread](../lib/cardano/state_thread.html).

use cardano/assets.{AssetName, PolicyId}
use cardano/nullifier.{Proof}
use cardano/nullifier
use cardano/nullifier_shard
use cardano/state_thread
use cardano/transaction.{OutputReference, Transaction}

pub type Datum {
  root: ByteArray,
}

pub type Redeemer {
  nullifier: ByteArray,
  proof: Proof,
}

validator sharded_nullifier(
  shard_count: Int,
  shard_index: Int,
  set_policy: PolicyId,
  set_name: AssetName,
) {
  spend(
    datum: Option<Datum>,
    redeemer: Redeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(Datum { root }) = datum
    // Reject any nullifier that isn't this shard's responsibility.
    expect nullifier_shard.in_shard(redeemer.nullifier, shard_count, shard_index)
    let updated_root =
      nullifier.spend(root, redeemer.nullifier, redeemer.proof)
    expect Datum { root: new_root } =
      state_thread.continuing_datum(self, own_ref, set_policy, set_name)
    new_root == updated_root
  }

  else(_) {
    fail
  }
}
