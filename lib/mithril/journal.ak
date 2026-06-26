//// Decoders for the Oakshield RISC0 guest journals.
////
//// Two fixed-offset layouts:
////
//// - **chain proof** (`oaks_comp`, 148 bytes): attests a Mithril tip and its
////   certified `CardanoTransactionsMerkleRoot`. This is what a tip registry
////   stores on-chain.
//// - **tx inclusion** (`oaks_tx`): attests that N Cardano transactions are
////   Merkle-included under a `tx_merkle_root` that a chain proof certified.
////
//// Both are application byte layouts, independent of the proof system. The
//// RISC0 → public-input lift in [crypto/risc0](../crypto/risc0.html) hashes
//// the whole journal, so verifying the proof binds these bytes; decoding only
//// reads fields out of an already-bound journal.

use aiken/builtin
use aiken/primitive/bytearray

fn u32_le(b: ByteArray, off: Int) -> Int {
  bytearray.to_int_little_endian(builtin.slice_bytearray(off, 4, b))
}

fn u64_le(b: ByteArray, off: Int) -> Int {
  bytearray.to_int_little_endian(builtin.slice_bytearray(off, 8, b))
}

fn sl(b: ByteArray, off: Int, len: Int) -> ByteArray {
  builtin.slice_bytearray(off, len, b)
}

// ── chain proof (oaks_comp), 148 bytes ──────────────────────────────────

/// Length of the chain-proof journal.
pub const chain_proof_length: Int = 148

/// Decoded chain-proof journal: a certified Mithril tip.
pub type ChainTip {
  /// Mithril network genesis cert digest (`journal[0..32]`).
  genesis_hash: ByteArray,
  /// Mithril tip cert digest (`journal[32..64]`).
  tip_hash: ByteArray,
  /// Certified `CardanoTransactionsMerkleRoot` (`journal[108..140]`).
  tx_merkle_root: ByteArray,
  /// Cardano block number at the tip (`journal[140..148]`, u64 LE).
  block_number: Int,
}

/// Decode a 148-byte chain-proof journal. Fails if the length is wrong.
/// Consumed off this library's path by a tip-registry minter, which stores the
/// certified `tx_merkle_root` for [mithril/tip](./tip.html) to read back.
pub fn decode_chain_proof(journal: ByteArray) -> ChainTip {
  expect bytearray.length(journal) == chain_proof_length
  ChainTip {
    genesis_hash: sl(journal, 0, 32),
    tip_hash: sl(journal, 32, 32),
    tx_merkle_root: sl(journal, 108, 32),
    block_number: u64_le(journal, 140),
  }
}

// ── tx inclusion (oaks_tx) ──────────────────────────────────────────────

/// Fixed header length before the per-transaction records.
pub const tx_inclusion_header_length: Int = 116

const tx_base_len: Int = 48

const typed_root_len: Int = 32

/// Decoded `oaks_tx` journal header. The transaction records that follow are
/// queried with [tx_committed](#tx_committed) rather than materialised.
pub type TxInclusion {
  /// The certified root the inclusion was proven against (`journal[0..32]`).
  /// A consumer MUST bind this to a trusted on-chain root.
  tx_merkle_root: ByteArray,
  /// The certificate tip the inclusion was based on (`journal[32..64]`).
  tip_hash: ByteArray,
  /// Provenance: tip → genesis (`journal[64..96]`).
  genesis_hash: ByteArray,
  /// Tip's LatestBlockNumber (`journal[96..104]`, u64 LE).
  cert_block_number: Int,
  /// 1 = bare-hash leaf (v1), 2 = composite leaf binding block/slot (v2).
  proof_version: Int,
  /// Assurance level: 0 = Inclusion, 1 = Bound, 2 = Components. Per-tx records
  /// are 80 bytes iff `mode == 2` (a typed component-tree root is appended);
  /// modes 0 and 1 are 48 bytes.
  mode: Int,
  /// Number of transaction records.
  tx_count: Int,
}

/// Decode the `oaks_tx` journal header and assert the byte length matches the
/// declared record count and layout. Fails on an unknown `proof_version`/`mode`
/// or any size mismatch. The caller must ensure `proof_version`/`mode` match the
/// network the certified root came from (see README security notes).
pub fn decode_tx_inclusion(journal: ByteArray) -> TxInclusion {
  expect bytearray.length(journal) >= tx_inclusion_header_length
  let proof_version = u32_le(journal, 104)
  let mode = u32_le(journal, 108)
  let tx_count = u32_le(journal, 112)
  // Reject unknown header variants rather than leaving the proof binding as the
  // only gate; this also pins the per-record layout for the length check below.
  expect proof_version == 1 || proof_version == 2
  expect mode == 0 || mode == 1 || mode == 2
  // Full-length check: the declared layout must match the bytes, so record
  // scans can't read past the end or accept a truncated journal.
  expect
    bytearray.length(journal) == tx_inclusion_header_length + tx_count * per_tx_len(
      mode,
    )
  TxInclusion {
    tx_merkle_root: sl(journal, 0, 32),
    tip_hash: sl(journal, 32, 32),
    genesis_hash: sl(journal, 64, 32),
    cert_block_number: u64_le(journal, 96),
    proof_version,
    mode,
    tx_count,
  }
}

// Per-record size: 80 bytes only for Components (mode 2), 48 otherwise.
// Matches the prover ABI (oakshield_common TxInclusionProofOutput).
fn per_tx_len(mode: Int) -> Int {
  if mode == 2 {
    tx_base_len + typed_root_len
  } else {
    tx_base_len
  }
}

/// True iff `tx_id` (32 bytes) appears among the journal's transaction
/// records. Pass the [TxInclusion](#TxInclusion) you already decoded to avoid
/// re-parsing the header.
pub fn tx_committed(journal: ByteArray, decoded: TxInclusion, tx_id: ByteArray) -> Bool {
  let stride = per_tx_len(decoded.mode)
  let end = tx_inclusion_header_length + decoded.tx_count * stride
  scan_records(journal, tx_inclusion_header_length, end, stride, tx_id)
}

fn scan_records(
  journal: ByteArray,
  pos: Int,
  end: Int,
  stride: Int,
  tx_id: ByteArray,
) -> Bool {
  if pos >= end {
    False
  } else if sl(journal, pos, 32) == tx_id {
    True
  } else {
    scan_records(journal, pos + stride, end, stride, tx_id)
  }
}
