use cardano/address.{Address, Script}
use cardano/assets
use cardano/nullifier
use cardano/transaction.{Input, InlineDatum, Output, OutputReference, Transaction}
use cardano/transaction
use nullifier_spend
use nullifier_spend.{Redeemer, SetDatum}

const script: ByteArray = #"00000000000000000000000000000000000000000000000000000002"

const a_nullifier: ByteArray =
  #"1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b"

fn addr() -> Address {
  Address { payment_credential: Script(script), stake_credential: None }
}

const own_ref: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

fn set_output(root: ByteArray) -> Output {
  Output {
    address: addr(),
    value: assets.zero,
    datum: InlineDatum(SetDatum { root }),
    reference_script: None,
  }
}

// A correct spend: insert the first nullifier (empty proof) and continue with
// the updated root.
test nullifier_spend_accepts_fresh() {
  let old_root = #"0000000000000000000000000000000000000000000000000000000000000000"
  let new_root = nullifier.spend(#"0000000000000000000000000000000000000000000000000000000000000000", a_nullifier, [])
  let input =
    Input { output_reference: own_ref, output: set_output(old_root) }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [input],
      outputs: [set_output(new_root)],
    }
  nullifier_spend.nullifier_spend.spend(
    Some(SetDatum { root: old_root }),
    Redeemer { nullifier: a_nullifier, proof: [] },
    own_ref,
    tx,
  )
}

// Continuing output carries the wrong root → rejected.
test nullifier_spend_rejects_wrong_output_root() {
  let old_root = #"0000000000000000000000000000000000000000000000000000000000000000"
  let input =
    Input { output_reference: own_ref, output: set_output(old_root) }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [input],
      outputs: [set_output(old_root)],
    }
  !nullifier_spend.nullifier_spend.spend(
    Some(SetDatum { root: old_root }),
    Redeemer { nullifier: a_nullifier, proof: [] },
    own_ref,
    tx,
  )
}
