//// Example (path A): prove a Cardano transaction is in the Mithril-certified
//// set, on mainnet-viable rails.
////
//// The certified `tx_merkle_root` is read from a tip registry as a reference
//// input (current tip or an archived tip); the redeemer carries a RISC0
//// `oaks_tx` proof attesting the transaction's inclusion under that root. No
//// Merkle hashing happens on-chain — the proof discharges it, and on-chain we
//// only verify the proof (a BLS pairing) and bind its root to the reference
//// input. See [mithril/tx_inclusion](../lib/mithril/tx_inclusion.html).
////
//// Parameters: the `oaks_tx` verification key + RISC0 platform parameters,
//// and the policy id of the tip registry whose reference inputs we trust.
////
//// Aborts on malformed input or a failed binding (bad byte lengths,
//// off-curve points, a missing tip reference input, a root mismatch); returns
//// False only on a well-formed but invalid proof.

use cardano/assets.{PolicyId}
use cardano/transaction.{OutputReference, Transaction}
use crypto/groth16.{Proof, VerificationKey}
use crypto/risc0.{Risc0Params}
use mithril/tip.{RootSource}
use mithril/tip
use mithril/tx_inclusion as inclusion

pub type Redeemer {
  proof: Proof,
  journal: ByteArray,
  tx_id: ByteArray,
  source: RootSource,
}

validator tx_inclusion(
  vk: VerificationKey,
  params: Risc0Params,
  registry_policy: PolicyId,
) {
  spend(
    _datum: Option<Data>,
    redeemer: Redeemer,
    _utxo: OutputReference,
    self: Transaction,
  ) {
    let certified_root =
      tip.read_certified_root(self, registry_policy, redeemer.source)
    inclusion.verify_inclusion(
      redeemer.proof,
      redeemer.journal,
      vk,
      params,
      certified_root,
      redeemer.tx_id,
    )
  }

  else(_) {
    fail
  }
}
