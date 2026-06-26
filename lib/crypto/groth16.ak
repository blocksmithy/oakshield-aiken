//// Groth16 verifier over BLS12-381 — gnark's outer verifier, loop path.
////
//// Verifies a gnark-style Groth16 proof that carries a single BSB22
//// commitment-public-wire (`n_commitments = 1`). Works on any Plutus V3
//// network from Chang onward: the inner-product over `ic` is a plain
//// scalar-mul/add fold, requiring no MSM builtin.
////
//// Curve-pure: it knows nothing about RISC0 or Mithril. `public` is an opaque
//// list of BLS12-381 Fr scalars; see [crypto/risc0](./risc0.html) for deriving
//// them from a RISC0 receipt.
////
//// Shape checks run before any curve work, decompression (CIP-0381) enforces
//// subgroup membership, and identity points are rejected on every proof
//// element. Precondition: the key must come from a gnark BSB22 circuit that
//// commits no public wire (`committed = [[]]`) and constrains the commitment
//// challenge in-circuit. Pin it as `sha256(vk.cardano.bin)` and parse on-chain
//// with [wire.parse_vk](../wire.html#parse_vk) (which asserts `committed = [[]]`)
//// rather than constructing the `VerificationKey` value by hand.

use aiken/builtin
use aiken/collection/list
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/g2
use aiken/crypto/bls12_381/pairing
use aiken/crypto/bls12_381/scalar
use aiken/primitive/bytearray
use crypto/hash_to_field

// BLS12-381 compressed point sizes, in bytes.
const g1_size: Int = 48

const g2_size: Int = 96

/// A BSB22 commitment: a compressed G1 point plus its uncompressed form.
///
/// `compressed` (48 B) is decompressed for arithmetic. `uncompressed`
/// (96 B = `x_be ‖ y_be`, gnark's `G1Affine.Marshal()`) is the hash-to-field
/// challenge preimage, used verbatim — it is never decompressed or cross-checked
/// against `compressed`. A mismatched pair cannot forge a proof: the BSB22
/// circuit constrains the challenge to the real commitment, so under Groth16
/// soundness no satisfying `(A, B, C)` exists for a decoupled `uncompressed`.
pub type Commitment {
  /// 48-byte compressed G1; decompressed for arithmetic.
  compressed: ByteArray,
  /// 96-byte uncompressed G1 (`x_be ‖ y_be`); the hash-to-field preimage, used verbatim.
  uncompressed: ByteArray,
}

/// A Groth16 proof with one BSB22 commitment and its proof-of-knowledge.
pub type Proof {
  /// Proof element A — 48-byte compressed G1.
  a: ByteArray,
  /// Proof element B — 96-byte compressed G2.
  b: ByteArray,
  /// Proof element C — 48-byte compressed G1.
  c: ByteArray,
  /// BSB22 commitments; length must equal `vk.n_commitments`.
  commitments: List<Commitment>,
  /// Proof-of-knowledge for the commitments — 48-byte compressed G1.
  pok: ByteArray,
}

/// A Groth16 verification key. All group elements are stored compressed and
/// decompressed at verification time. `ic` has `1 + public_input_count +
/// n_commitments` entries: `ic[0]` is the constant wire, the next
/// `public_input_count` scale the public inputs, and the trailing
/// `n_commitments` scale the BSB22 challenges.
pub type VerificationKey {
  /// 48-byte compressed G1.
  alpha_g1: ByteArray,
  /// 96-byte compressed G2.
  beta_g2: ByteArray,
  /// 96-byte compressed G2.
  gamma_g2: ByteArray,
  /// 96-byte compressed G2.
  delta_g2: ByteArray,
  /// `1 + public_input_count + n_commitments` compressed G1 points (48 B each).
  ic: List<ByteArray>,
  /// Pedersen commitment-key G2 points (length `n_commitments`).
  pedersen_g: List<ByteArray>,
  /// Negated Pedersen σ G2 points (length `n_commitments`).
  pedersen_g_sigma_neg: List<ByteArray>,
  /// Number of BSB22 commitments; must be 1.
  n_commitments: Int,
  /// Number of public inputs the circuit expects.
  public_input_count: Int,
}

/// Structural validation of a verification key: the byte-length and arity
/// invariants `verify` relies on. `n_commitments` is pinned to 1 because the
/// Pedersen-pairing block destructures the head of each commitment list;
/// any other value is unsound here. Does not check curve-semantic validity
/// of the key (that is the operator's responsibility off-chain).
pub fn validate_vk_shape(vk: VerificationKey) -> Bool {
  and {
    vk.n_commitments == 1,
    vk.public_input_count >= 0,
    bytearray.length(vk.alpha_g1) == g1_size,
    bytearray.length(vk.beta_g2) == g2_size,
    bytearray.length(vk.gamma_g2) == g2_size,
    bytearray.length(vk.delta_g2) == g2_size,
    list.length(vk.ic) == 1 + vk.public_input_count + vk.n_commitments,
    list.all(vk.ic, fn(p) { bytearray.length(p) == g1_size }),
    list.length(vk.pedersen_g) == 1,
    list.length(vk.pedersen_g_sigma_neg) == 1,
    list.all(vk.pedersen_g, fn(p) { bytearray.length(p) == g2_size }),
    list.all(vk.pedersen_g_sigma_neg, fn(p) { bytearray.length(p) == g2_size }),
  }
}

/// Verify a Groth16 proof against a verification key and public inputs.
///
/// `public` must be exactly `vk.public_input_count` BLS12-381 Fr scalars,
/// each canonical (in `[0, r)`). Returns `True` iff both the main Groth16
/// equation and the Pedersen commitment pairing hold.
pub fn verify(proof: Proof, public: List<Int>, vk: VerificationKey) -> Bool {
  // ── length / shape checks (before any cryptographic work) ──────────────
  expect validate_vk_shape(vk)
  expect list.length(public) == vk.public_input_count
  expect list.length(proof.commitments) == vk.n_commitments
  expect bytearray.length(proof.a) == g1_size
  expect bytearray.length(proof.b) == g2_size
  expect bytearray.length(proof.c) == g1_size
  expect bytearray.length(proof.pok) == g1_size
  expect
    list.all(
      proof.commitments,
      fn(c) {
        bytearray.length(c.compressed) == g1_size && bytearray.length(c.uncompressed) == g2_size
      },
    )

  // nC = 1: the single head of each Pedersen list.
  expect [pedersen_g_bytes] = vk.pedersen_g
  expect [pedersen_g_sigma_neg_bytes] = vk.pedersen_g_sigma_neg

  // Every public input must be a canonical scalar; reject otherwise.
  expect list.all(public, fn(p) { p >= 0 && p < scalar.field_prime })

  // ── decompression (subgroup-checked by the builtins) ───────────────────
  let a_g1 = g1.decompress(proof.a)
  let b_g2 = g2.decompress(proof.b)
  let c_g1 = g1.decompress(proof.c)
  let pok_g1 = g1.decompress(proof.pok)
  let commitment_g1s =
    list.map(proof.commitments, fn(c) { g1.decompress(c.compressed) })

  let alpha_g1 = g1.decompress(vk.alpha_g1)
  let beta_g2 = g2.decompress(vk.beta_g2)
  let gamma_g2 = g2.decompress(vk.gamma_g2)
  let delta_g2 = g2.decompress(vk.delta_g2)
  let ic_points = list.map(vk.ic, g1.decompress)
  let pedersen_g_0 = g2.decompress(pedersen_g_bytes)
  let pedersen_g_sigma_neg_0 = g2.decompress(pedersen_g_sigma_neg_bytes)

  // ── point-at-infinity rejection on every proof-supplied point ──────────
  expect !g1.equal(a_g1, g1.zero)
  expect !g2.equal(b_g2, g2.zero)
  expect !g1.equal(c_g1, g1.zero)
  expect !g1.equal(pok_g1, g1.zero)
  expect list.all(commitment_g1s, fn(c) { !g1.equal(c, g1.zero) })

  // ── BSB22 challenges: h_j = HashToField(commitment_j.uncompressed) ──
  // This circuit family commits no public wire (gnark
  // `PublicAndCommitmentCommitted = [[]]`), so the challenge preimage is exactly
  // the commitment's marshalled bytes — nothing is appended. The pinned VK's
  // shape is asserted at parse time (`wire.parse_vk`: every committed count is
  // 0) and `n_commitments == 1` in `validate_vk_shape`.
  let commitment_hashes = commitment_challenges(proof.commitments)

  // ── augmented kSum ─────────────────────────────────────────────────────
  // kSum = ic[0] + Σ public_i·ic[i+1] + Σ h_j·ic[nbPub+1+j] + Σ commitment_j
  expect [ic_0, ..ic_rest] = ic_points
  let all_scalars = list.concat(public, commitment_hashes)
  let k_after_msm = fold_scalar_mul(ic_rest, all_scalars, ic_0)
  let k_sum =
    list.foldl(commitment_g1s, k_after_msm, fn(c, acc) { g1.add(acc, c) })
  // kSum aggregates attacker-influenced terms; reject the identity here too, so
  // e(kSum, γ) can't be collapsed.
  expect !g1.equal(k_sum, g1.zero)

  // ── main check: e(A,B) == e(α,β) · e(kSum,γ) · e(C,δ) ──────────────────
  let ml_ab = pairing.miller_loop(a_g1, b_g2)
  let ml_alpha_beta = pairing.miller_loop(alpha_g1, beta_g2)
  let ml_ksum_gamma = pairing.miller_loop(k_sum, gamma_g2)
  let ml_c_delta = pairing.miller_loop(c_g1, delta_g2)
  let ml_rhs = mul_ml(mul_ml(ml_alpha_beta, ml_ksum_gamma), ml_c_delta)
  let main_ok = pairing.final_exponentiation(ml_ab, ml_rhs)

  // ── Pedersen pairing (nC=1): e(commitment, GσNeg) · e(pok, G) == 1 ─────
  expect [commitment_0, ..] = commitment_g1s
  let pok_neg = builtin.bls12_381_g1_neg(pok_g1)
  let pedersen_ok =
    pairing.final_exponentiation(
      pairing.miller_loop(commitment_0, pedersen_g_sigma_neg_0),
      pairing.miller_loop(pok_neg, pedersen_g_0),
    )

  main_ok && pedersen_ok
}

/// Walk `(points, scalars)` in lockstep, scaling each point by its scalar
/// and folding into `acc`. Lengths are equal by the checks in `verify`; the
/// final branch fails if that invariant is broken.
fn fold_scalar_mul(
  points: List<G1Element>,
  scalars: List<Int>,
  acc: G1Element,
) -> G1Element {
  when (points, scalars) is {
    ([], []) -> acc
    ([p, ..pt], [s, ..st]) ->
      fold_scalar_mul(pt, st, g1.add(acc, builtin.bls12_381_g1_scalar_mul(s, p)))
    _ -> fail @"ic / scalars length mismatch (post-length-check invariant violated)"
  }
}

fn mul_ml(a: MillerLoopResult, b: MillerLoopResult) -> MillerLoopResult {
  builtin.bls12_381_mul_miller_loop_result(a, b)
}

// The BSB22 challenge for each commitment: HashToField over the commitment's
// uncompressed marshalled bytes. This circuit family commits no public wire, so
// nothing is appended to the preimage (see `verify`). With `n_commitments == 1`
// this maps a single commitment to a single challenge.
fn commitment_challenges(commitments: List<Commitment>) -> List<Int> {
  list.map(commitments, fn(c) { hash_to_field.hash_to_field_h(c.uncompressed) })
}
