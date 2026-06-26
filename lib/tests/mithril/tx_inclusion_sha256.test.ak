//// Unit tests for `mithril/tx_inclusion_sha256` (v0.2.0 — domain-separated
//// leaf/node/anchor prefixes kept, implicit v1/v2 dispatch via `block_le8`
//// length, raw-`List<ByteArray>` siblings).
////
//// Self-consistent property tests + constant pins. Upstream golden vectors live
//// in `tx_inclusion_sha256_live_*` / `_vectors` (their Y values are unchanged
//// from v0.2.0 since the prefixed recipe is unchanged).

use aiken/builtin
use aiken/collection/list
use aiken/primitive/bytearray
use mithril/tx_inclusion_sha256

// ── shared constants ─────────────────────────────────────────────────

const txid_42: ByteArray =
  #"4242424242424242424242424242424242424242424242424242424242424242"

const x_start: ByteArray =
  #"a01dc04eb01e5b1aabd9c5f3ad42068a907b6e89e1eb4f2e4a85d2eedcf01a82"

const block_le8: ByteArray = #"0260430000000000"

const slot_le8: ByteArray = #"e5e5e50600000000"

const empty_root: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

// node = sha256(0x01 ‖ left ‖ right), matching the module's private node_hash.
fn node(left: ByteArray, right: ByteArray) -> ByteArray {
  builtin.sha2_256(bytearray.concat(#"01", bytearray.concat(left, right)))
}

// 40 Zero-siblings — sentinel proof for "this leaf is the only entry at slot N".
// Caller expands the table off chain; on chain we pass the raw 32-byte values.
fn forty_zero_siblings() -> List<ByteArray> {
  list.map(
    list.range(0, 39),
    fn(k) {
      expect Some(z) = list.at(tx_inclusion_sha256.zeros, k)
      z
    },
  )
}

// ── constant pins (load-bearing) ─────────────────────────────────────

test test_zeros_table_has_41_entries() {
  list.length(tx_inclusion_sha256.zeros) == 41
}

/// `zeros[0]` is the all-zeros byte string by spec.
test test_zeros_0_is_all_zero() {
  expect Some(z0) = list.at(tx_inclusion_sha256.zeros, 0)
  z0 == empty_root
}

/// `zeros[40]` matches the upstream-published empty-tree root.
test test_zeros_40_matches_upstream_reference_value() {
  expect Some(z40) = list.at(tx_inclusion_sha256.zeros, 40)
  z40 == #"56530aa5d958fb0a28d5dbaa6c2a2d3857e93c43faaf60265b59159ccb06a5e4"
}

/// Spot-check `zeros[k+1] == sha256(0x01 ‖ zeros[k] ‖ zeros[k])`. If this drifts,
/// the table was generated against the wrong recipe and every off-chain
/// proof-expander will compute wrong values.
test test_zeros_chain_is_consistent_at_index_1() {
  expect Some(z0) = list.at(tx_inclusion_sha256.zeros, 0)
  expect Some(z1) = list.at(tx_inclusion_sha256.zeros, 1)
  z1 == node(z0, z0)
}

test test_zeros_chain_is_consistent_at_index_40() {
  expect Some(z39) = list.at(tx_inclusion_sha256.zeros, 39)
  expect Some(z40) = list.at(tx_inclusion_sha256.zeros, 40)
  z40 == node(z39, z39)
}

// ── leaf_hash + anchor_hash structural tests ─────────────────────────

/// v1 dispatch (empty block_le8): leaf = sha256(0x00 ‖ txid).
test test_leaf_hash_v1_is_sha256_of_txid_only() {
  tx_inclusion_sha256.leaf_hash(txid_42, #"", #"") == builtin.sha2_256(
    bytearray.concat(#"00", txid_42),
  )
}

/// v2 dispatch (8-byte block_le8 + slot_le8): leaf = sha256(0x00 ‖ txid ‖ block ‖ slot).
test test_leaf_hash_v2_is_sha256_of_txid_block_slot() {
  let expected =
    builtin.sha2_256(
      bytearray.concat(
        #"00",
        bytearray.concat(txid_42, bytearray.concat(block_le8, slot_le8)),
      ),
    )
  tx_inclusion_sha256.leaf_hash(txid_42, block_le8, slot_le8) == expected
}

/// v1 and v2 leaves for the same txid are DISTINCT — the implicit dispatch must
/// produce different hashes for different payloads, else Y values collide.
test test_leaf_hash_v1_and_v2_differ() {
  tx_inclusion_sha256.leaf_hash(txid_42, #"", #"") != tx_inclusion_sha256.leaf_hash(
    txid_42,
    block_le8,
    slot_le8,
  )
}

/// `anchor_hash(x) = sha256(0x03 ‖ x)` — distinct from a leaf by the prefix.
test test_anchor_hash_is_sha256_of_x_start() {
  tx_inclusion_sha256.anchor_hash(x_start) == builtin.sha2_256(
    bytearray.concat(#"03", x_start),
  )
}

/// Domain separation: a v1 leaf and the anchor over the same 32-byte input
/// differ, because the leaf/anchor prefixes differ.
test test_leaf_and_anchor_domain_separated() {
  tx_inclusion_sha256.leaf_hash(x_start, #"", #"") != tx_inclusion_sha256.anchor_hash(
    x_start,
  )
}

// ── verify_inclusion property tests ──────────────────────────────────

/// A leaf at slot 0 in an otherwise-empty depth-40 tree: build Y by walking 40
/// zero-siblings with the same prefixed node hash, then assert acceptance.
test test_verify_inclusion_v1_at_index_0_with_all_zero_siblings() {
  let leaf = tx_inclusion_sha256.leaf_hash(txid_42, #"", #"")
  let zeros40 = forty_zero_siblings()
  let expected_y = list.foldl(zeros40, leaf, fn(sib, cur) { node(cur, sib) })
  tx_inclusion_sha256.verify_inclusion(expected_y, txid_42, #"", #"", 0, zeros40)
}

/// Same for v2 — leaf format change must not break the walker.
test test_verify_inclusion_v2_at_index_0_with_all_zero_siblings() {
  let leaf = tx_inclusion_sha256.leaf_hash(txid_42, block_le8, slot_le8)
  let zeros40 = forty_zero_siblings()
  let expected_y = list.foldl(zeros40, leaf, fn(sib, cur) { node(cur, sib) })
  tx_inclusion_sha256.verify_inclusion(
    expected_y,
    txid_42,
    block_le8,
    slot_le8,
    0,
    zeros40,
  )
}

/// Tampering ANY sibling breaks the walk → verifier rejects.
test adv_verify_inclusion_rejects_tampered_first_sibling() {
  let leaf = tx_inclusion_sha256.leaf_hash(txid_42, #"", #"")
  let zeros40 = forty_zero_siblings()
  let expected_y = list.foldl(zeros40, leaf, fn(sib, cur) { node(cur, sib) })
  let tampered =
    [
      #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      ..list.drop(zeros40, 1)
    ]
  !tx_inclusion_sha256.verify_inclusion(expected_y, txid_42, #"", #"", 0, tampered)
}

/// Wrong sibling count (< 40) rejects via the up-front length pin.
test adv_verify_inclusion_rejects_short_siblings() fail {
  let leaf = tx_inclusion_sha256.leaf_hash(txid_42, #"", #"")
  let too_few = list.take(forty_zero_siblings(), 39)
  tx_inclusion_sha256.verify_inclusion(leaf, txid_42, #"", #"", 0, too_few)
}

/// A non-32-byte sibling rejects via the sibling-length pin.
test adv_verify_inclusion_rejects_wrong_length_sibling() fail {
  let leaf = tx_inclusion_sha256.leaf_hash(txid_42, #"", #"")
  let bad = [#"00", ..list.drop(forty_zero_siblings(), 1)]
  tx_inclusion_sha256.verify_inclusion(leaf, txid_42, #"", #"", 0, bad)
}

/// Mixed v1/v2 length signal (block_le8 = #"" but slot_le8 = 8 B) rejects.
test adv_verify_inclusion_rejects_mixed_v1_v2_signal() fail {
  let leaf = tx_inclusion_sha256.leaf_hash(txid_42, #"", #"")
  tx_inclusion_sha256.verify_inclusion(
    leaf,
    txid_42,
    #"",
    slot_le8,
    0,
    forty_zero_siblings(),
  )
}

/// Non-32-byte txid rejects via the wire-shape pin.
test adv_verify_inclusion_rejects_short_txid() fail {
  let short_txid: ByteArray = #"42424242"
  tx_inclusion_sha256.verify_inclusion(
    empty_root,
    short_txid,
    #"",
    #"",
    0,
    forty_zero_siblings(),
  )
}

/// Out-of-range leaf_index (≥ 2^40) rejects.
test adv_verify_inclusion_rejects_out_of_range_index() fail {
  tx_inclusion_sha256.verify_inclusion(
    empty_root,
    txid_42,
    #"",
    #"",
    1099511627776,
    forty_zero_siblings(),
  )
}

/// Negative leaf_index rejects.
test adv_verify_inclusion_rejects_negative_index() fail {
  tx_inclusion_sha256.verify_inclusion(
    empty_root,
    txid_42,
    #"",
    #"",
    -1,
    forty_zero_siblings(),
  )
}
