use aiken/builtin
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/transaction.{OutputReference}
use dev/testkit
use mithril/tx_inclusion_sha256
use txtree_inclusion
use txtree_inclusion.{Redeemer, YDatum}

const y_policy: ByteArray =
  #"00000000000000000000000000000000000000000000000000000099"

const y_name: ByteArray = "y"

const txid_42: ByteArray =
  #"4242424242424242424242424242424242424242424242424242424242424242"

const ref_y: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

const own_ref: OutputReference =
  OutputReference { transaction_id: #"", output_index: 1 }

// 40 Zero siblings: the leaf is the only entry in the tree. Callers
// pre-expand the `zeros[k]` table to a raw `List<ByteArray>` of 40
// entries before submitting.
fn all_zero_siblings() -> List<ByteArray> {
  list.map(list.range(0, 39), fn(k) {
    expect Some(z) = list.at(tx_inclusion_sha256.zeros, k)
    z
  })
}

// Y root for "txid_42 alone at slot 0 in an empty depth-40 tree", computed
// inline against the algorithm (prefixed node = sha256(0x01 ‖ l ‖ r)). Avoids
// hand-pinning a constant that drifts with any spec change.
fn expected_y_for_txid_42_v1_at_slot_0() -> ByteArray {
  let leaf = tx_inclusion_sha256.leaf_hash(txid_42, #"", #"")
  list.foldl(
    all_zero_siblings(),
    leaf,
    fn(sib, cur) {
      builtin.sha2_256(bytearray.concat(#"01", bytearray.concat(cur, sib)))
    },
  )
}

fn run(txid: ByteArray, siblings: List<ByteArray>, with_ytoken: Bool) -> Bool {
  let refs =
    if with_ytoken {
      [
        testkit.script_input(
          y_policy,
          y_policy,
          y_name,
          YDatum { y_root: expected_y_for_txid_42_v1_at_slot_0() },
          ref_y,
        ),
      ]
    } else {
      []
    }
  txtree_inclusion.txtree_inclusion.spend(
    y_policy,
    y_name,
    None,
    Redeemer { txid, block_le8: #"", slot_le8: #"", leaf_index: 0, siblings },
    own_ref,
    testkit.tx([], refs, []),
  )
}

// A committed tx with its inclusion proof unlocks against the
// y-token's Y root.
test txtree_inclusion_accepts_member() {
  run(txid_42, all_zero_siblings(), True)
}

// A different tx does not reconstruct Y → reject.
test txtree_inclusion_rejects_non_member() {
  !run(
    #"4343434343434343434343434343434343434343434343434343434343434343",
    all_zero_siblings(),
    True,
  )
}

// No y-token reference input → the registry lookup aborts.
test txtree_inclusion_rejects_missing_ytoken() fail {
  run(txid_42, all_zero_siblings(), False)
}
