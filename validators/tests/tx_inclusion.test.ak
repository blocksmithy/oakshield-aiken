//// The success path verifies a real `oaks_tx` Groth16 proof, whose prover is
//// still in flight — so it can't be exercised on-chain yet. These tests cover
//// the demonstrable non-crypto logic: reading the certified root from a tip
//// registry reference input and binding the journal to it.

use cardano/transaction.{OutputReference}
use dev/ceremony
use dev/testkit
use mithril/tip.{FromTip, SingletonDatum, TipData}
use tx_inclusion
use tx_inclusion.{Redeemer}

const registry_policy: ByteArray =
  #"00000000000000000000000000000000000000000000000000000007"

const ref_tip: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

const own_ref: OutputReference =
  OutputReference { transaction_id: #"", output_index: 1 }

// Synthetic oaks_tx journal (mode 0, 2 txs); its committed root is 0x34..34.
const tx_journal: ByteArray =
  #"343434343434343434343434343434343434343434343434343434343434343409090909090909090909090909090909090909090909090909090909090909092525252525252525252525252525252525252525252525252525252525252525dfbacd00000000000100000000000000020000001d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b000000000000000000000000000000009dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f50300000000000000000000000000000000"

const present_tx: ByteArray =
  #"1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b"

// Tip whose certified root (0x99..99) does NOT match the journal's (0x34..34).
fn tip_data() -> TipData {
  TipData {
    genesis_hash: #"2525252525252525252525252525252525252525252525252525252525252525",
    tip_hash: #"0909090909090909090909090909090909090909090909090909090909090909",
    tx_merkle_root: #"9999999999999999999999999999999999999999999999999999999999999999",
    block_number: 100,
    mint_time_ms: 0,
  }
}

// The validator reads the tip's root from the reference input and binds the
// journal to it; a mismatch aborts (before the pairing). This exercises the
// registry NFT lookup, datum decode, and root binding in the validator context.
test tx_inclusion_rejects_root_mismatch() fail {
  let datum = SingletonDatum { current_tip: Some(tip_data()), prev_cert_hash: None }
  let tip_in =
    testkit.script_input(registry_policy, registry_policy, "singleton", datum, ref_tip)
  let tx = testkit.tx([], [tip_in], [])
  tx_inclusion.tx_inclusion.spend(
    ceremony.verification_key(),
    ceremony.risc0_params(),
    registry_policy,
    None,
    Redeemer {
      proof: ceremony.proof(),
      journal: tx_journal,
      tx_id: present_tx,
      source: FromTip,
    },
    own_ref,
    tx,
  )
}

// Missing the tip reference input → the registry lookup aborts.
test tx_inclusion_rejects_missing_tip() fail {
  tx_inclusion.tx_inclusion.spend(
    ceremony.verification_key(),
    ceremony.risc0_params(),
    registry_policy,
    None,
    Redeemer {
      proof: ceremony.proof(),
      journal: tx_journal,
      tx_id: present_tx,
      source: FromTip,
    },
    own_ref,
    testkit.tx([], [], []),
  )
}
