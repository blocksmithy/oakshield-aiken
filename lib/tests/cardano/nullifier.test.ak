//// Tests for the minimal `cardano/nullifier` API (v0.2.0).
////
//// Only `spend` + `derive` are exposed publicly. `is_spent` /
//// `is_unspent` / `from_root` / `root` / `empty` accessors were
//// removed in v0.2.0 — soundness depends only on `spend`'s internal
//// non-membership check + replay-abort.

use cardano/nullifier

// Exercise the public `empty_root` constant (not a local literal).
const empty_root: ByteArray = nullifier.empty_root

const a_nullifier: ByteArray =
  #"1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b"

const b_nullifier: ByteArray =
  #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

// The empty-set root is the 32-byte MPF empty-trie root.
test empty_root_is_mpf_empty() {
  nullifier.empty_root == #"0000000000000000000000000000000000000000000000000000000000000000"
}

// The first insert into an empty trie uses an empty proof. The
// returned root is a 32-byte value distinct from the empty-root
// marker, so downstream validators have something fresh to write
// into the continuing output's datum.
test first_insert_yields_fresh_root() {
  let new_root = nullifier.spend(empty_root, a_nullifier, [])
  new_root != empty_root
}

// Different nullifiers from an empty set yield different roots —
// replay protection depends on the trie's structure encoding which
// keys have been inserted.
test distinct_nullifiers_yield_distinct_roots() {
  let root_a = nullifier.spend(empty_root, a_nullifier, [])
  let root_b = nullifier.spend(empty_root, b_nullifier, [])
  root_a != root_b
}

// Replay: spending the same nullifier a second time against the
// post-insert root must abort. The empty proof is no longer valid
// (the key is now in the trie), so `spend`'s internal exclusion
// check rejects.
test replay_rejected() fail {
  let after = nullifier.spend(empty_root, a_nullifier, [])
  // Attempting to re-insert with an empty proof: excluding(key, [])
  // would yield zeros, but `after` is no longer zeros — proof
  // verification fails.
  nullifier.spend(after, a_nullifier, []) != #""
}

// `derive` is domain-separated: same committed value under different
// domains gives different nullifiers, so cross-protocol nullifier
// reuse is structurally prevented.
test derive_is_domain_separated() {
  let domain_a: ByteArray = #"6f616b735f747874726565"  // "oaks_txtree"
  let domain_b: ByteArray = #"6f616b735f747800000000"  // arbitrary alt domain
  let committed: ByteArray =
    #"04efbc6fc3b8732dac8dc8b08c420d2be37ecfec50e1cd8d35e62c4d314e3428"
  nullifier.derive(domain_a, committed) != nullifier.derive(domain_b, committed)
}

// `derive` is deterministic — same domain + same committed value
// always yields the same nullifier (so the spend-side derivation
// from the consume-side txid always matches).
test derive_is_deterministic() {
  let domain: ByteArray = #"6f616b735f747874726565"
  let committed: ByteArray =
    #"04efbc6fc3b8732dac8dc8b08c420d2be37ecfec50e1cd8d35e62c4d314e3428"
  nullifier.derive(domain, committed) == nullifier.derive(domain, committed)
}
