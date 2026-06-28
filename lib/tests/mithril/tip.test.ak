use cardano/address.{Address, Script}
use cardano/assets
use cardano/transaction.{Input, InlineDatum, Output, OutputReference, Transaction}
use cardano/transaction
use mithril/tip.{FromHistory, FromTip, HistoricalDatum, SingletonDatum, TipData}

const policy: ByteArray = #"00000000000000000000000000000000000000000000000000000001"

// A deployment-chosen current-tip NFT name (NOT a library-enforced "singleton").
// Using a non-default name here is the regression guard against re-hardcoding.
const tip_name: ByteArray = "mithril_tip"

const root: ByteArray =
  #"3434343434343434343434343434343434343434343434343434343434343434"

const a_tip_hash: ByteArray =
  #"0909090909090909090909090909090909090909090909090909090909090909"

fn registry_addr() -> Address {
  Address { payment_credential: Script(policy), stake_credential: None }
}

fn nft_input(name: ByteArray, datum: Data) -> Input {
  Input {
    output_reference: OutputReference { transaction_id: #"", output_index: 0 },
    output: Output {
      address: registry_addr(),
      value: assets.from_asset(policy, name, 1),
      datum: InlineDatum(datum),
      reference_script: None,
    },
  }
}

fn a_tip_data() -> TipData {
  TipData {
    genesis_hash: #"2525252525252525252525252525252525252525252525252525252525252525",
    tip_hash: a_tip_hash,
    tx_merkle_root: root,
    block_number: 100,
    mint_time_ms: 0,
  }
}

test read_root_from_tip() {
  let datum = SingletonDatum { current_tip: Some(a_tip_data()), prev_cert_hash: None }
  let tx =
    Transaction { ..transaction.placeholder, reference_inputs: [nft_input(tip_name, datum)] }
  // Check the root AND a non-root field, so a wrong struct projection is caught.
  let t = tip.read_tip(tx, policy, tip_name, FromTip)
  and {
    t.tx_merkle_root == root,
    t.block_number == 100,
    t.tip_hash == a_tip_hash,
  }
}

test read_root_from_history() {
  let datum = HistoricalDatum { tip_data: a_tip_data(), prev_cert_hash: None }
  let tx =
    Transaction {
      ..transaction.placeholder,
      reference_inputs: [nft_input(a_tip_hash, datum)],
    }
  tip.read_certified_root(tx, policy, tip_name, FromHistory { tip_hash: a_tip_hash }) == root
}

// A historical UTxO whose NFT name disagrees with its datum tip_hash is rejected.
test history_name_must_match_datum() fail {
  let datum = HistoricalDatum { tip_data: a_tip_data(), prev_cert_hash: None }
  let tx =
    Transaction {
      ..transaction.placeholder,
      reference_inputs: [nft_input("deadbeef", datum)],
    }
  tip.read_certified_root(tx, policy, tip_name, FromHistory { tip_hash: "deadbeef" }) == root
}

// No registry reference input present → fails (uniqueness lookup).
test tip_missing_ref_input() fail {
  tip.read_certified_root(transaction.placeholder, policy, tip_name, FromTip) == root
}

// Current-tip NFT present but current_tip is None → fails at `expect Some(tip)`.
test tip_current_none() fail {
  let datum = SingletonDatum { current_tip: None, prev_cert_hash: None }
  let tx =
    Transaction { ..transaction.placeholder, reference_inputs: [nft_input(tip_name, datum)] }
  tip.read_certified_root(tx, policy, tip_name, FromTip) == root
}

// Current-tip NFT carrying the wrong datum shape → fails at the datum cast.
test tip_wrong_datum_shape() fail {
  let wrong = HistoricalDatum { tip_data: a_tip_data(), prev_cert_hash: None }
  let tx =
    Transaction { ..transaction.placeholder, reference_inputs: [nft_input(tip_name, wrong)] }
  tip.read_certified_root(tx, policy, tip_name, FromTip) == root
}

// Two reference inputs both bearing the current-tip NFT → ambiguity rejected.
test tip_ambiguous_nft() fail {
  let datum = SingletonDatum { current_tip: Some(a_tip_data()), prev_cert_hash: None }
  let tx =
    Transaction {
      ..transaction.placeholder,
      reference_inputs: [nft_input(tip_name, datum), nft_input(tip_name, datum)],
    }
  tip.read_certified_root(tx, policy, tip_name, FromTip) == root
}

// FromHistory with no matching reference input → fails.
test history_missing_ref_input() fail {
  tip.read_certified_root(
    transaction.placeholder,
    policy,
    tip_name,
    FromHistory { tip_hash: a_tip_hash },
  ) == root
}
