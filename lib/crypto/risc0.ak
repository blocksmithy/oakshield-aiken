//// RISC0 receipt → BLS12-381 public inputs.
////
//// A RISC0 STARK proved directly over BLS12-381 (`risc0-groth16-bls`) attests
//// the statement "I verified a RISC0 receipt with this `ReceiptClaim` digest
//// under this control root." [lift_to_scalars](#lift_to_scalars) reproduces
//// that statement's 5 native public inputs from the committed journal and the
//// platform parameters, so [crypto/groth16](./groth16.html) can check the proof
//// against them — or use [verify_receipt](#verify_receipt) for both in one call.
////
//// This module performs no curve arithmetic: it only hashes the journal
//// through the `ReceiptClaim` digest chain and reads the result out as
//// BLS12-381 Fr scalars. Cardano only ever operates on BLS12-381.

use aiken/builtin
use aiken/primitive/bytearray
use crypto/groth16.{Proof, VerificationKey}
use crypto/groth16

/// RISC0 platform parameters that pin a specific guest and prover release.
///
/// - `image_id` (32 B): the guest ELF image id, used as `pre.digest` in the
///   `ReceiptClaim` digest chain. This is the binding to a specific program.
/// - `control_root` (32 B): the recursion control root for the prover release.
/// - `control_id_fr`: the recursion control id as a BLS12-381 Fr, read
///   little-endian from the 32-byte control id (`to_int_little_endian`).
pub type Risc0Params {
  /// 32-byte guest ELF image id (`pre.digest`); binds a specific program.
  image_id: ByteArray,
  /// 32-byte recursion control root for the prover release.
  control_root: ByteArray,
  /// Recursion control id as a BLS12-381 Fr: `to_int_little_endian` of the
  /// 32-byte control id.
  control_id_fr: Int,
}

// ── digest-chain constants ──────────────────────────────────────────────

// 32 zero bytes — Digest::ZERO (input.digest = None, assumptions = empty).
const zero32: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

// u32_LE(0) ‖ u32_LE(0) — sys_exit = Halted(0), user_exit = 0.
const exit_words_halted_ok: ByteArray = #"0000000000000000"

// u16_LE(2) — tagged-struct len(digests) for Output.
const len_two_le: ByteArray = #"0200"

// u16_LE(4) — tagged-struct len(digests) for ReceiptClaim.
const len_four_le: ByteArray = #"0400"

// sha256("risc0.Output").
const tag_output: ByteArray =
  #"77eafeb366a78b47747de0d7bb176284085ff5564887009a5be63da32d3559d4"

// sha256("risc0.ReceiptClaim").
const tag_receipt_claim: ByteArray =
  #"cb1fefcd1f2d9a64975cbbbf6e161e2914434b0cbb9960b84df5d717e86b48af"

// SystemState::HALTED with pc = 0:
// sha256( sha256("risc0.SystemState") ‖ ZERO32 ‖ u32_le(0) ‖ u16_le(1) ).
const post_digest_halted_pc0: ByteArray =
  #"a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2"

// Split a 32-byte digest into (low, high) 128-bit integers. Interpreting
// each half as little-endian equals "reverse to BE then read BE".
fn split_digest(d: ByteArray) -> (Int, Int) {
  expect bytearray.length(d) == 32
  let low = bytearray.to_int_little_endian(builtin.slice_bytearray(0, 16, d))
  let high = bytearray.to_int_little_endian(builtin.slice_bytearray(16, 16, d))
  (low, high)
}

/// Reproduce the RISC0 `ReceiptClaim::digest` for an `ok()`-shaped receipt
/// (Halted(0), no input, no assumptions) committing `journal`, under
/// `image_id`.
///
/// ```
/// journal_digest = sha256(journal)
/// output_digest  = sha256( tag_output ‖ journal_digest ‖ ZERO32 ‖ u16_le(2) )
/// claim_digest   = sha256( tag_receipt_claim ‖ ZERO32 ‖ image_id
///                        ‖ post_digest ‖ output_digest
///                        ‖ u32_le(0) ‖ u32_le(0) ‖ u16_le(4) )
/// ```
pub fn claim_digest(journal: ByteArray, image_id: ByteArray) -> ByteArray {
  let journal_digest = builtin.sha2_256(journal)
  let output_digest =
    tag_output
      |> bytearray.concat(journal_digest)
      |> bytearray.concat(zero32)
      |> bytearray.concat(len_two_le)
      |> builtin.sha2_256
  tag_receipt_claim
    |> bytearray.concat(zero32)
    |> bytearray.concat(image_id)
    |> bytearray.concat(post_digest_halted_pc0)
    |> bytearray.concat(output_digest)
    |> bytearray.concat(exit_words_halted_ok)
    |> bytearray.concat(len_four_le)
    |> builtin.sha2_256
}

/// Derive the 5 **native** BLS12-381 Fr public inputs (`n_limbs_per_scalar = 1`)
/// for a RISC0-receipt Groth16 proof proved directly over BLS12-381:
///
/// ```
/// [0] split(control_root).low
/// [1] split(control_root).high
/// [2] split(claim_digest).low
/// [3] split(claim_digest).high
/// [4] control_id_fr          (the program's control id, as an Fr)
/// ```
///
/// The values are used directly (no limb decomposition). `control_id_fr` is a
/// BLS12-381 Fr; its range is enforced by `groth16.verify`'s per-public-input
/// canonical check, so it is not bounds-checked here.
pub fn lift_to_scalars(journal: ByteArray, params: Risc0Params) -> List<Int> {
  expect bytearray.length(params.image_id) == 32
  expect bytearray.length(params.control_root) == 32
  let cd = claim_digest(journal, params.image_id)
  let (cr_lo, cr_hi) = split_digest(params.control_root)
  let (cd_lo, cd_hi) = split_digest(cd)
  [cr_lo, cr_hi, cd_lo, cd_hi, params.control_id_fr]
}

/// Verify a native-BLS RISC0 receipt proof in one call: derive the public
/// inputs from the committed `journal` + pinned `params` ([lift_to_scalars](#lift_to_scalars)),
/// then verify the Groth16 proof against them. The public inputs are bound to
/// the program (`image_id`) and journal — a proof for a different journal is
/// rejected. Use this rather than wiring `lift_to_scalars` + `groth16.verify`
/// by hand.
pub fn verify_receipt(
  vk: VerificationKey,
  params: Risc0Params,
  proof: Proof,
  journal: ByteArray,
) -> Bool {
  groth16.verify(proof, lift_to_scalars(journal, params), vk)
}
