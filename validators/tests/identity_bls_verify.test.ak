use cardano/transaction.{OutputReference, Transaction}
use cardano/transaction
use dev/ceremony
use identity_bls_verify
use identity_bls_verify.{Redeemer}

const utxo: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

fn empty_tx() -> Transaction {
  transaction.placeholder
}

// End-to-end: the validator accepts the production ceremony proof, deriving the
// public inputs from the committed journal.
test identity_bls_verify_accepts() {
  identity_bls_verify.identity_bls_verify.spend(
    ceremony.verification_key(),
    ceremony.risc0_params(),
    None,
    Redeemer { proof: ceremony.proof(), journal: ceremony.journal },
    utxo,
    empty_tx(),
  )
}

// A different journal yields different derived publics → the proof no longer
// verifies (this is the journal binding working at the validator level).
test identity_bls_verify_rejects_wrong_journal() {
  !identity_bls_verify.identity_bls_verify.spend(
    ceremony.verification_key(),
    ceremony.risc0_params(),
    None,
    Redeemer { proof: ceremony.proof(), journal: #"8801000000000000" },
    utxo,
    empty_tx(),
  )
}
