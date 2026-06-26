//// Hash-to-field for gnark's BSB22 commitment-public-wire on BLS12-381.
////
//// Implements RFC 9380 `expand_message_xmd` over SHA-256, then unsigned
//// big-endian reduction modulo the BLS12-381 scalar field. Specialised for
//// the single-commitment case gnark emits: `count = 1`, `lenInBytes = 48`,
//// `ell = 2` (two SHA-256 blocks, the second truncated to 16 bytes). Three
//// SHA-256 calls per invocation.
////
//// Constants are pinned to gnark v0.15.0. The domain-separation tag is
//// `bsb22-commitment`.

use aiken/builtin
use aiken/crypto/bls12_381/scalar
use aiken/primitive/bytearray

// DST_prime = DST ‖ I2OSP(len(DST), 1), where DST = ASCII "bsb22-commitment"
// (16 bytes); so DST_prime = DST ‖ 0x10 (17 bytes).
const dst_prime: ByteArray = #"62736232322d636f6d6d69746d656e7410"

// Z_pad = s_in_bytes (SHA-256 block size) zero bytes.
const z_pad: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// I2OSP(lenInBytes, 2) = I2OSP(48, 2) = 0x0030.
const l_i_b_str: ByteArray = #"0030"

// RFC 9380 `expand_message_xmd` over SHA-256 for `lenInBytes = 48` (`ell = 2`),
// specialised to the gnark BSB22 case. Returns the 48-byte uniform output;
// reduction mod r is done by `hash_to_field_h`.
fn expand_message_xmd_48(msg: ByteArray) -> ByteArray {
  // msg_prime = Z_pad ‖ msg ‖ l_i_b_str ‖ I2OSP(0,1) ‖ DST_prime
  let msg_prime =
    z_pad
      |> bytearray.concat(msg)
      |> bytearray.concat(l_i_b_str)
      |> bytearray.concat(#"00")
      |> bytearray.concat(dst_prime)
  let b_0 = builtin.sha2_256(msg_prime)
  let b_1 =
    builtin.sha2_256(b_0 |> bytearray.concat(#"01") |> bytearray.concat(dst_prime))
  let b_2 =
    builtin.sha2_256(
      bytearray.xor_bytes(b_0, b_1, False)
        |> bytearray.concat(#"02")
        |> bytearray.concat(dst_prime),
    )
  // uniform_48 = b_1 (32 B) ‖ b_2[0..16] (slice end inclusive ⇒ 0..15 = 16 B)
  bytearray.concat(b_1, bytearray.slice(b_2, 0, 15))
}

/// Full hash-to-field: `expand_message_xmd_48` then reduce mod the
/// BLS12-381 scalar field. Returns an `Int` in `[0, r)`.
pub fn hash_to_field_h(msg: ByteArray) -> Int {
  expand_message_xmd_48(msg)
    |> bytearray.to_int_big_endian
    |> reduce_fr
}

fn reduce_fr(x: Int) -> Int {
  x % scalar.field_prime
}
