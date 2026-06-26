//// Example: full on-chain verification of a RISC0-STARK-over-BLS12-381 proof
//// (the `small-ceremony-2026-06` production format).
////
//// It does NOT trust the redeemer's public inputs. It derives them from the
//// committed journal and the pinned platform parameters
//// ([crypto/risc0.lift_to_scalars](../lib/crypto/risc0.html)),
//// then verifies the Groth16 proof against them ([crypto/groth16](../lib/crypto/groth16.html)).
//// That binds the proof to *this* program (`image_id`) and *this* journal:
////
//// - `control_root` (public[0,1]) is pinned via `params.control_root`,
//// - `claim_digest` (public[2,3]) is recomputed from `image_id` + `journal`,
//// - `control_id` (public[4]) is pinned via `params.control_id_fr`.
////
//// The verifying key is a validator parameter — pin the ceremony VK (its
//// `sha256` is the off-chain gate value). Native publics (`n_limbs = 1`).
////
//// Aborts on malformed input (wrong byte lengths, non-canonical scalars,
//// off-curve points, a journal/image mismatch); returns False only on a
//// well-formed but invalid proof.

use cardano/transaction.{OutputReference, Transaction}
use crypto/groth16.{Proof, VerificationKey}
use crypto/risc0.{Risc0Params}

pub type Redeemer {
  /// The Groth16 proof in Cardano wire form.
  proof: Proof,
  /// The guest's committed journal (binds the public inputs).
  journal: ByteArray,
}

validator identity_bls_verify(vk: VerificationKey, params: Risc0Params) {
  spend(
    _datum: Option<Data>,
    redeemer: Redeemer,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    risc0.verify_receipt(vk, params, redeemer.proof, redeemer.journal)
  }

  else(_) {
    fail
  }
}
