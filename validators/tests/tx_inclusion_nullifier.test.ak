use cardano/address.{Address, Script}
use cardano/assets
use cardano/transaction.{Input, InlineDatum, Output, OutputReference, Transaction}
use cardano/transaction
use tx_inclusion_nullifier
use tx_inclusion_nullifier.{SetDatum}

const script: ByteArray = #"00000000000000000000000000000000000000000000000000000003"

const set_policy: ByteArray = #"00000000000000000000000000000000000000000000000000000009"

const set_name: ByteArray = #"6e756c6c6966696572"

const a_root: ByteArray =
  #"abababababababababababababababababababababababababababababababab"

const own_ref: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

fn addr() -> Address {
  Address { payment_credential: Script(script), stake_credential: None }
}

// A state-thread output: at the script address, carrying the set NFT + datum.
fn set_output(root: ByteArray, with_nft: Bool) -> Output {
  Output {
    address: addr(),
    value: if with_nft {
      assets.from_asset(set_policy, set_name, 1)
    } else {
      assets.zero
    },
    datum: InlineDatum(SetDatum { root }),
    reference_script: None,
  }
}

fn input() -> Input {
  Input { output_reference: own_ref, output: set_output(a_root, True) }
}

fn tx(outputs: List<Output>) -> Transaction {
  Transaction { ..transaction.placeholder, inputs: [input()], outputs }
}

// Reads the new root from the unique state-thread continuing output.
test continuing_root_reads_thread_output() {
  let new_root =
    #"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
  tx_inclusion_nullifier.continuing_set_root(
    tx([set_output(new_root, True)]),
    own_ref,
    set_policy,
    set_name,
  ) == new_root
}

// No continuing output carrying the NFT → fails (set can't be dropped).
test continuing_root_missing_nft_output() fail {
  tx_inclusion_nullifier.continuing_set_root(
    tx([set_output(a_root, False)]),
    own_ref,
    set_policy,
    set_name,
  ) == a_root
}

// Two outputs carrying the NFT → ambiguous, fails (set can't be forked).
test continuing_root_ambiguous_output() fail {
  tx_inclusion_nullifier.continuing_set_root(
    tx([set_output(a_root, True), set_output(a_root, True)]),
    own_ref,
    set_policy,
    set_name,
  ) == a_root
}

// Continuing output carries a non-SetDatum → fails.
test continuing_root_wrong_datum() fail {
  let bad =
    Output {
      address: addr(),
      value: assets.from_asset(set_policy, set_name, 1),
      datum: InlineDatum(42),
      reference_script: None,
    }
  tx_inclusion_nullifier.continuing_set_root(tx([bad]), own_ref, set_policy, set_name) == a_root
}
