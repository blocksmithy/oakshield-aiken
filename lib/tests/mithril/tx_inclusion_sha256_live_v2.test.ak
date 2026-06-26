//// **Live v2 IVC golden vectors from the upstream `oaks_txtree`
//// on-chain package** — `oaks_txtree_onchain_package.tar.gz`
//// delivered 2026-06-26. Source: live Mithril preview aggregator.
//// v2 leaves bind `(txid, block_number, slot_number)` per the
//// upstream spec (`spec/ON_CHAIN_SPEC.md`):
////
////   leaf_v2 = sha256(0x00 ‖ txid ‖ block_number_LE8 ‖ slot_number_LE8)
////
//// Each step's Y commits only **sealed** ranges (`end <= beacon+1`).
//// `bound_x` is the cert-signed Blake2s root the validator
//// cross-checks against the Mithril tip — and is also the y-token's
//// asset_name in our 32-byte-cap-aware scheme.
////
//// 2 accept tests (one per step), exercising:
////   - V2 leaf-binding (txid + block + slot)
////   - 40-level SHA-256 walk against two distinct Y roots
////   - 11-non-zero-sibling compressed proof shape (deeper-than-v1
////     because v2's sealed range count is ~10× v1's tx count)

use aiken/collection/list
use mithril/tx_inclusion_sha256

/// Resolve `zeros[k]` from the module's pinned zero-subtree table.
fn z(k: Int) -> ByteArray {
  expect Some(v) = list.at(tx_inclusion_sha256.zeros, k)
  v
}

// ── live v2 IVC vectors ─────────────────────────────────────────


// ── step_00 — v2 live preview, beacon 4416570, b_start 4415490, frontier 4416570 ──
/// bound_x: 2ff13be0e11490ab7e283df869cd9d9f6f12f9f19daf592855c2c3c91d461eb7
const step_00_y_root: ByteArray =
  #"7a999bc9e9d093b4a5a19807b64a997072d87118d55628a9aa4591096d82ddb8"
const step_00_tx0_txid: ByteArray =
  #"50dd99a4c9e89ab3a63fe074c3e9ceb29fcd62add7efe970ee44e29a2e3ce2a8"
const step_00_tx0_block_le8: ByteArray =
  #"0260430000000000"
const step_00_tx0_slot_le8: ByteArray =
  #"e5e5e50600000000"
fn step_00_tx0_siblings() -> List<ByteArray> {
  [
    #"1333b813b50a19117d0ef7273f2c0934598ded6e99a165313c32e7ab849d4123", #"c7c34a802ce621dbb4ecadaa59429b93a72b3a4c87ba211ceeba41a9e4f18a33", #"ce270451c2785036f5fab33465f20ff79d926aa320b1c910b008da37c835235b", #"7ad8924fa7c261c16bc7e59f786eb401b9f7952249783919fddd59bfa17720ba",
    #"fdaad9632e36610f2cb6e2ec51bd39d3e8b3890b587a437de2df054bc26017d5", #"560ad0993972408bb773d06be50b69c811120d945f4d2e39641d6afe45a60efa", #"1123f3df0edc740e60c4f45e9491fdc3e905836e1922328acd7eedbfe61c8a91", #"0fd49d6f9279491ddeb33c19472c1825f9c4d165ca3282b7b37db80db5d4d708",
    #"11cd646e81c0fb59c90c6c349e98e2680ba27fa8626399d45249a89e4a6d8c35", #"0535a1050f096d33523d41dca34e7884cbd36dcef51ade6a9aeb143a51810f70", #"40a9a656c28c9293b15634dc8ec663ea0441a556a49970c07f2786274a6f91e0", z(11),
    z(12), z(13), z(14), z(15),
    z(16), z(17), z(18), z(19),
    z(20), z(21), z(22), z(23),
    z(24), z(25), z(26), z(27),
    z(28), z(29), z(30), z(31),
    z(32), z(33), z(34), z(35),
    z(36), z(37), z(38), z(39),
  ]
}

// ── step_01 — v2 live preview, beacon 4417050, b_start 4415490, frontier 4417050 ──
/// bound_x: 80973a990adabbcff1beb97ab42fb7fdad167d35d8f80e52173cabf66e237cc6
const step_01_y_root: ByteArray =
  #"33931a820cd0b9756637d1cc73e04ebd67b2a4d35e249e005f967e5b4b206e99"
const step_01_tx0_txid: ByteArray =
  #"50dd99a4c9e89ab3a63fe074c3e9ceb29fcd62add7efe970ee44e29a2e3ce2a8"
const step_01_tx0_block_le8: ByteArray =
  #"0260430000000000"
const step_01_tx0_slot_le8: ByteArray =
  #"e5e5e50600000000"
fn step_01_tx0_siblings() -> List<ByteArray> {
  [
    #"1333b813b50a19117d0ef7273f2c0934598ded6e99a165313c32e7ab849d4123", #"c7c34a802ce621dbb4ecadaa59429b93a72b3a4c87ba211ceeba41a9e4f18a33", #"ce270451c2785036f5fab33465f20ff79d926aa320b1c910b008da37c835235b", #"7ad8924fa7c261c16bc7e59f786eb401b9f7952249783919fddd59bfa17720ba",
    #"fdaad9632e36610f2cb6e2ec51bd39d3e8b3890b587a437de2df054bc26017d5", #"560ad0993972408bb773d06be50b69c811120d945f4d2e39641d6afe45a60efa", #"1123f3df0edc740e60c4f45e9491fdc3e905836e1922328acd7eedbfe61c8a91", #"0fd49d6f9279491ddeb33c19472c1825f9c4d165ca3282b7b37db80db5d4d708",
    #"11cd646e81c0fb59c90c6c349e98e2680ba27fa8626399d45249a89e4a6d8c35", #"0535a1050f096d33523d41dca34e7884cbd36dcef51ade6a9aeb143a51810f70", #"f9e7255072a41f768b7cad941dc68b39f3fbf56321df5f557e1a198644f79f91", z(11),
    z(12), z(13), z(14), z(15),
    z(16), z(17), z(18), z(19),
    z(20), z(21), z(22), z(23),
    z(24), z(25), z(26), z(27),
    z(28), z(29), z(30), z(31),
    z(32), z(33), z(34), z(35),
    z(36), z(37), z(38), z(39),
  ]
}

// ── 2 accept tests, one per step ────────────────────────────────

test test_live_v2_step_00_anchor_tx0_accept() {
  tx_inclusion_sha256.verify_inclusion(
    step_00_y_root, step_00_tx0_txid,
    step_00_tx0_block_le8, step_00_tx0_slot_le8, 1, step_00_tx0_siblings(),
  )
}

test test_live_v2_step_01_tx0_accept() {
  tx_inclusion_sha256.verify_inclusion(
    step_01_y_root, step_01_tx0_txid,
    step_01_tx0_block_le8, step_01_tx0_slot_le8, 1, step_01_tx0_siblings(),
  )
}
