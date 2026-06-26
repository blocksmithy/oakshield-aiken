//// Verified-tip registry datum schema and certified-root readers.
////
//// These datum types mirror the on-chain state of the `groth16-wrap-cardano`
//// tip registry, so any contract can read its certified
//// `CardanoTransactionsMerkleRoot` as a reference input — the current tip
//// (held by a `singleton` NFT) or any archived tip (held by a per-tip NFT
//// whose asset name is the tip's `tip_hash`).
////
//// The datum layouts must stay byte-identical to the registry that produces
//// them; treat them as a shared on-chain ABI.

use cardano/assets.{AssetName, PolicyId}
use cardano/registry
use cardano/transaction.{InlineDatum, Transaction}

/// Asset name of the singleton NFT marking the current-tip UTxO.
pub const singleton_name: AssetName = "singleton"

/// Per-tip data extracted from a verified chain proof. Held by the singleton
/// while current, copied verbatim into a historical UTxO once superseded.
pub type TipData {
  /// 32-byte Mithril network genesis cert digest.
  genesis_hash: ByteArray,
  /// 32-byte Mithril tip cert digest; also the per-tip NFT's asset name.
  tip_hash: ByteArray,
  /// 32-byte certified `CardanoTransactionsMerkleRoot`.
  tx_merkle_root: ByteArray,
  /// Cardano block number at the tip.
  block_number: Int,
  /// POSIX ms when the tip was recorded on-chain.
  mint_time_ms: Int,
}

/// Datum of the current-tip (singleton) UTxO. `current_tip` is `None` only
/// before the first update.
pub type SingletonDatum {
  /// The current tip, or `None` before the first update.
  current_tip: Option<TipData>,
  /// Back-pointer to the previous tip's `tip_hash`, if any.
  prev_cert_hash: Option<ByteArray>,
}

/// Datum of an archived-tip UTxO. The per-tip NFT's asset name is
/// `tip_data.tip_hash`.
pub type HistoricalDatum {
  /// The archived tip's data.
  tip_data: TipData,
  /// Back-pointer to the previous tip's `tip_hash`, if any.
  prev_cert_hash: Option<ByteArray>,
}

/// Which certified root to read.
pub type RootSource {
  /// The current tip (singleton NFT UTxO).
  FromTip
  /// An archived tip, identified by its `tip_hash` (= per-tip NFT name).
  FromHistory { tip_hash: ByteArray }
}

/// Read the full certified [TipData](#TipData) from the chosen registry
/// reference input — current tip (singleton NFT) or an archived tip (per-tip
/// NFT named by its `tip_hash`). Gives access to `block_number` / `tip_hash` /
/// `genesis_hash` for freshness or provenance checks, not just the root. Fails
/// if the reference input is missing/ambiguous, the datum is the wrong shape,
/// or (history) the named tip does not match its datum.
///
/// To require a recent root, compare `tip.block_number` or `mint_time_ms`
/// against the transaction's validity range (e.g. assert `mint_time_ms` is
/// within a bounded window of the lower validity bound).
pub fn read_tip(
  self: Transaction,
  policy_id: PolicyId,
  source: RootSource,
) -> TipData {
  when source is {
    FromTip -> {
      let input = registry.reference_input_with_nft(self, policy_id, singleton_name)
      expect InlineDatum(inner) = input.output.datum
      expect datum: SingletonDatum = inner
      expect Some(tip) = datum.current_tip
      tip
    }
    FromHistory { tip_hash } -> {
      let input = registry.reference_input_with_nft(self, policy_id, tip_hash)
      expect InlineDatum(inner) = input.output.datum
      expect datum: HistoricalDatum = inner
      // Bind the NFT name to the datum so a mislabelled archive can't lie.
      expect datum.tip_data.tip_hash == tip_hash
      datum.tip_data
    }
  }
}

/// The certified `tx_merkle_root` of the chosen tip — a convenience over
/// [read_tip](#read_tip) for the common case.
pub fn read_certified_root(
  self: Transaction,
  policy_id: PolicyId,
  source: RootSource,
) -> ByteArray {
  read_tip(self, policy_id, source).tx_merkle_root
}
