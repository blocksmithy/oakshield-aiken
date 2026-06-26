//// Sharded nullifier sets — for parallel, non-contending spends.
////
//// A single nullifier-set UTxO serialises all spends (one per block). Splitting
//// the space into `shard_count` independent state UTxOs lets that many spends
//// proceed concurrently. The shard is chosen by the nullifier's own bytes, so
//// each nullifier has exactly one home shard — the shards are disjoint and
//// global uniqueness holds with no cross-shard coordination.
////
//// Deploy one [cardano/nullifier](./nullifier.html) set per shard; each shard's
//// validator asserts [in_shard](#in_shard) before inserting, so a nullifier can
//// only ever be spent in its home shard. (Nullifiers here are typically hashes,
//// e.g. a `tx_id`, so their leading byte is already uniform.)

use aiken/primitive/bytearray

/// The home shard of `nullifier`: its first byte modulo `shard_count`.
///
/// Requires `shard_count >= 1` (asserted) and a non-empty `nullifier`
/// (`bytearray.at` aborts on empty — a safe-fail). Only the first byte is used,
/// so a uniform partition needs `shard_count <= 256`; larger values leave high
/// shards empty but remain disjoint and correct.
pub fn shard_of(nullifier: ByteArray, shard_count: Int) -> Int {
  expect shard_count >= 1
  bytearray.at(nullifier, 0) % shard_count
}

/// True iff `nullifier` belongs to shard `shard_index` (of `shard_count`).
/// A shard validator asserts this before inserting into its set.
pub fn in_shard(nullifier: ByteArray, shard_count: Int, shard_index: Int) -> Bool {
  shard_of(nullifier, shard_count) == shard_index
}
