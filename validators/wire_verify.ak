//// Example: verify a RISC0 receipt whose proof arrives as RAW wire bytes.
////
//// The redeemer carries the prover's `proof.cardano.bin` bytes verbatim; the
//// validator parses them on-chain ([wire.parse_proof](../lib/wire.html)) and
//// verifies ([crypto/risc0.verify_receipt](../lib/crypto/risc0.html)). This is
//// the raw-bytes redeemer pattern — the off-chain side passes prover bytes
//// directly, no PlutusData encoding of the proof.
////
//// `parse_proof` aborts on malformed wire bytes (wrong lengths, non-canonical
//// scalars, off-curve points); `verify_receipt` returns False only on a
//// well-formed but invalid proof.

use cardano/transaction.{OutputReference, Transaction}
use crypto/groth16.{VerificationKey}
use crypto/risc0.{Risc0Params}
use crypto/risc0
use wire

pub type Redeemer {
  /// The prover's `proof.cardano.bin` bytes.
  proof_wire: ByteArray,
  /// The committed journal (binds the public inputs).
  journal: ByteArray,
}

validator wire_verify(vk: VerificationKey, params: Risc0Params) {
  spend(
    _datum: Option<Data>,
    redeemer: Redeemer,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    risc0.verify_receipt(vk, params, wire.parse_proof(redeemer.proof_wire), redeemer.journal)
  }

  else(_) {
    fail
  }
}
