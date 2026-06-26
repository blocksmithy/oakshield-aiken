use cardano/transaction.{OutputReference}
use cardano/transaction
use dev/ceremony
use groth16_verify
use groth16_verify.{Datum}

const utxo: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

// Statement is committed in the datum; a valid proof of it unlocks.
test groth16_verify_accepts_real() {
  groth16_verify.groth16_verify.spend(
    ceremony.verification_key(),
    Some(Datum { public: ceremony.public() }),
    ceremony.proof(),
    utxo,
    transaction.placeholder,
  )
}

// A datum committing to a different statement (one flipped public input) is not
// satisfied by this proof.
test groth16_verify_rejects_wrong_statement() {
  expect [_first, ..rest] = ceremony.public()
  !groth16_verify.groth16_verify.spend(
    ceremony.verification_key(),
    Some(Datum { public: [1, ..rest] }),
    ceremony.proof(),
    utxo,
    transaction.placeholder,
  )
}
