//// Example: gate a spend on a SHA-256 tx-tree inclusion proof (`oaks_txtree`).
////
//// A trusted reference input (the "y-token", a unique NFT) carries the pinned
//// tree root `Y` and its leaf version in an inline datum. The redeemer supplies
//// a transaction id and its inclusion proof, and the spend succeeds iff the
//// proof reconstructs `Y`. The SNARK that certified `Y` is verified once
//// elsewhere; each inclusion check here is ~41 SHA-256 hashes
//// ([mithril/tx_inclusion_sha256](../lib/mithril/tx_inclusion_sha256.html)).
////
//// Aborts on a malformed proof (wrong sibling count, out-of-range index, bad
//// field lengths) or a missing y-token; returns False when the proof does not
//// reconstruct `Y`.

use cardano/assets.{AssetName, PolicyId}
use cardano/registry
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use mithril/tx_inclusion_sha256 as txtree

/// Datum of the y-token reference input: the pinned tree root.
/// (Equivalently, `Y` can be the y-token's asset name; this example
/// keeps it in the datum for clarity.) Leaf version is implicit on
/// the wire — v1 if `block_le8` is empty, v2 if it's 8 bytes
/// (matched on `slot_le8`).
pub type YDatum {
  y_root: ByteArray,
}

pub type Redeemer {
  txid: ByteArray,
  /// Empty (v1) or 8-byte little-endian block_number (v2).
  block_le8: ByteArray,
  /// Empty (v1) or 8-byte little-endian slot (v2). MUST match
  /// `block_le8`'s emptiness/length.
  slot_le8: ByteArray,
  leaf_index: Int,
  /// 40 pre-expanded 32-byte siblings — caller substitutes
  /// `zeros[k]` for empty branches before tx submission.
  siblings: List<ByteArray>,
}

validator txtree_inclusion(y_policy: PolicyId, y_name: AssetName) {
  spend(
    _datum: Option<Data>,
    redeemer: Redeemer,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    // Read Y from the trusted y-token reference input.
    let y_input = registry.reference_input_with_nft(self, y_policy, y_name)
    expect InlineDatum(inner) = y_input.output.datum
    expect YDatum { y_root } = inner

    txtree.verify_inclusion(
      y_root,
      redeemer.txid,
      redeemer.block_le8,
      redeemer.slot_le8,
      redeemer.leaf_index,
      redeemer.siblings,
    )
  }

  else(_) {
    fail
  }
}
