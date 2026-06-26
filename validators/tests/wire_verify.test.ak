use aiken/primitive/bytearray
use cardano/transaction.{OutputReference}
use cardano/transaction
use dev/ceremony
use wire_verify
use wire_verify.{Redeemer}

const utxo: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

// Accept the production proof passed as RAW wire bytes: the validator parses
// proof.cardano.bin on-chain, then verifies + binds the journal.
test wire_verify_accepts_raw_bytes() {
  wire_verify.wire_verify.spend(
    ceremony.verification_key(),
    ceremony.risc0_params(),
    None,
    Redeemer { proof_wire: ceremony.proof_raw, journal: ceremony.journal },
    utxo,
    transaction.placeholder,
  )
}

// A truncated proof wire is rejected by the decoder's exact-length guard.
test wire_verify_rejects_truncated() fail {
  wire_verify.wire_verify.spend(
    ceremony.verification_key(),
    ceremony.risc0_params(),
    None,
    Redeemer {
      proof_wire: bytearray.take(ceremony.proof_raw, 387),
      journal: ceremony.journal,
    },
    utxo,
    transaction.placeholder,
  )
}
