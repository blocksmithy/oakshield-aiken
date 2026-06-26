//// Example: unlock a UTxO by proving the statement it commits to.
////
//// The verification key is baked in as a validator parameter. The UTxO's datum
//// fixes the public inputs — the *statement* this UTxO will accept a proof of —
//// and the redeemer carries the proof. Spending requires a valid Groth16 proof
//// of exactly those public inputs.
////
//// The public inputs come from the on-chain datum, NOT the redeemer, so a
//// spender cannot substitute their own statement. This is the safe shape for
//// the curve-pure [crypto/groth16](../lib/crypto/groth16.html); for RISC0
//// receipts, [identity_bls_verify](./identity_bls_verify.html) derives the
//// public inputs from a journal instead.
////
//// Aborts on malformed input (wrong byte lengths, non-canonical scalars,
//// off-curve points); returns False only on a well-formed but invalid proof.

use cardano/transaction.{OutputReference, Transaction}
use crypto/groth16.{Proof, VerificationKey}

/// The statement (public inputs) this UTxO commits to accepting a proof of.
pub type Datum {
  public: List<Int>,
}

validator groth16_verify(vk: VerificationKey) {
  spend(
    datum: Option<Datum>,
    proof: Proof,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    expect Some(Datum { public }) = datum
    groth16.verify(proof, public, vk)
  }

  else(_) {
    fail
  }
}
