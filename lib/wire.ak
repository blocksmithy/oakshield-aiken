//// Decoders for the Cardano wire format the prover emits
//// (`vk.cardano.bin` / `proof.cardano.bin` / `public.cardano.bin`).
////
//// All multi-byte integers are big-endian `u32`; curve points are compressed
//// (G1 = 48 B, G2 = 96 B); field scalars are 32 B. These let a redeemer carry
//// the prover's raw bytes and have the validator parse them, and they back the
//// off-chain SDK's serialize/parse. Targets the native `risc0-groth16-bls`
//// wrap: one limb per public scalar (`n_limbs = 1`) and a VK that commits no
//// public wire (every BSB22 `committed` count is 0, asserted on parse).

use aiken/builtin
use aiken/primitive/bytearray
use crypto/groth16.{Commitment, Proof, VerificationKey}

fn u32(b: ByteArray, off: Int) -> Int {
  bytearray.to_int_big_endian(builtin.slice_bytearray(off, 4, b))
}

fn sl(b: ByteArray, off: Int, len: Int) -> ByteArray {
  builtin.slice_bytearray(off, len, b)
}

// ── public inputs ───────────────────────────────────────────────────────────

/// Decode `public.cardano.bin` into the flat public-input vector (`n_inner_pub`
/// scalars, each read big-endian). The native wrap has exactly one limb per
/// scalar (`n_limbs_per_scalar == 1`), asserted here. Aborts on malformed bytes
/// (wrong length or header), so a malformed redeemer fails the script rather
/// than returning a value.
pub fn parse_public(b: ByteArray) -> List<Int> {
  let n_inner = u32(b, 0)
  let n_limbs = u32(b, 4)
  // Native (risc0-groth16-bls): exactly one limb per scalar.
  expect n_limbs == 1
  // Tie the counts to the actual byte length, so a crafted header can't drive
  // an unbounded read and a short/oversized buffer fails fast.
  expect bytearray.length(b) == 8 + n_inner * n_limbs * 32
  read_scalars(b, 8, n_inner * n_limbs)
}

fn read_scalars(b: ByteArray, off: Int, n: Int) -> List<Int> {
  if n == 0 {
    []
  } else {
    [bytearray.to_int_big_endian(sl(b, off, 32)), ..read_scalars(b, off + 32, n - 1)]
  }
}

// ── proof ───────────────────────────────────────────────────────────────────

/// Decode `proof.cardano.bin`: `A‖B‖C‖nC‖(commit_compressed‖commit_uncompressed)×nC‖pok`.
/// Aborts on malformed bytes (wrong length or header), so a malformed redeemer
/// fails the script rather than returning a value.
pub fn parse_proof(b: ByteArray) -> Proof {
  let n_c = u32(b, 192)
  // Bound the commitment loop to the buffer: an oversized `n_c` can't match the
  // declared total length (A‖B‖C‖nC ‖ nC×144 ‖ pok), so it fails before looping.
  expect bytearray.length(b) == 196 + n_c * 144 + 48
  let (commitments, off) = read_commitments(b, 196, n_c)
  Proof {
    a: sl(b, 0, 48),
    b: sl(b, 48, 96),
    c: sl(b, 144, 48),
    commitments,
    pok: sl(b, off, 48),
  }
}

fn read_commitments(b: ByteArray, off: Int, n: Int) -> (List<Commitment>, Int) {
  if n == 0 {
    ([], off)
  } else {
    let (rest, end) = read_commitments(b, off + 144, n - 1)
    (
      [
        Commitment { compressed: sl(b, off, 48), uncompressed: sl(b, off + 48, 96) },
        ..rest
      ],
      end,
    )
  }
}

// ── verifying key ────────────────────────────────────────────────────────────

/// Decode `vk.cardano.bin`:
/// `α‖β‖γ‖δ‖ic_count‖K[]‖nC‖(G‖GSigmaNeg)×nC‖(committed_count‖indices)×nC`.
/// `public_input_count` is derived as `ic_count - 1 - nC`. Every
/// `committed_count` must be 0 (the native circuit commits no public wire) — a
/// VK that commits wires fails here rather than mis-verifying. Aborts on
/// malformed bytes (wrong length or header), so a malformed redeemer fails the
/// script rather than returning a value.
pub fn parse_vk(b: ByteArray) -> VerificationKey {
  let ic_count = u32(b, 336)
  // Bound the ic loop to the buffer before reading it.
  expect bytearray.length(b) >= 340 + ic_count * 48
  let (ic, off1) = read_points(b, 340, ic_count, 48)
  let n_c = u32(b, off1)
  let (pedersen_g, pedersen_g_sigma_neg, off2) = read_pedersen(b, off1 + 4, n_c)
  // One-time VK-shape guard: every commitment commits no public wire.
  let off3 = expect_empty_committed(b, off2, n_c)
  // The parse must consume the whole input exactly — no trailing/missing bytes.
  expect off3 == bytearray.length(b)
  VerificationKey {
    alpha_g1: sl(b, 0, 48),
    beta_g2: sl(b, 48, 96),
    gamma_g2: sl(b, 144, 96),
    delta_g2: sl(b, 240, 96),
    ic,
    pedersen_g,
    pedersen_g_sigma_neg,
    n_commitments: n_c,
    public_input_count: ic_count - 1 - n_c,
  }
}

fn read_points(b: ByteArray, off: Int, n: Int, size: Int) -> (List<ByteArray>, Int) {
  if n == 0 {
    ([], off)
  } else {
    let (rest, end) = read_points(b, off + size, n - 1, size)
    ([sl(b, off, size), ..rest], end)
  }
}

fn read_pedersen(
  b: ByteArray,
  off: Int,
  n: Int,
) -> (List<ByteArray>, List<ByteArray>, Int) {
  if n == 0 {
    ([], [], off)
  } else {
    let (gs, gsns, end) = read_pedersen(b, off + 192, n - 1)
    ([sl(b, off, 96), ..gs], [sl(b, off + 96, 96), ..gsns], end)
  }
}

// Each commitment's committed-index list must be empty (`count == 0`): the
// native circuit commits no public wire. Asserts this and returns the offset
// past the `n` committed-count words (4 bytes each).
fn expect_empty_committed(b: ByteArray, off: Int, n: Int) -> Int {
  if n == 0 {
    off
  } else {
    expect u32(b, off) == 0
    expect_empty_committed(b, off + 4, n - 1)
  }
}
