//// Adversarial suite for [crypto/groth16](./groth16.html), run against the
//// real **native** production proof (`small-ceremony-2026-06`, 5 BLS12-381 Fr
//// public inputs) from [dev/ceremony](../dev/ceremony.html).
////
//// Tamper vectors are single-byte flips of the production proof's fields:
//// compressed group elements fail subgroup decompression (abort), while the
//// commitment's uncompressed preimage breaks the BSB22 challenge (returns
//// `False`).

use crypto/groth16.{Commitment, Proof, VerificationKey}
use crypto/groth16
use dev/ceremony

// ── valid proof ──────────────────────────────────────────────────────────────

test verify_real_proof() {
  groth16.verify(ceremony.proof(), ceremony.public(), ceremony.verification_key())
}

test vk_shape_valid() {
  groth16.validate_vk_shape(ceremony.verification_key())
}

// ── per-field proof tampering ────────────────────────────────────────────────
// A/B/pok/commitment.compressed are decompressed (subgroup-checked); a
// tampered field is not a valid subgroup point, so decompression aborts.

test adv_tampered_proof_a() fail {
  let p =
    Proof {
      ..ceremony.proof(),
      a: #"a9f7cbf487c8bb500a5f405fa576edbc1deba56da1d945b9530bb4a8f84185927b82ff9fcf97ee5195692ca62e4e4bc8",
    }
  groth16.verify(p, ceremony.public(), ceremony.verification_key())
}

test adv_tampered_proof_b() fail {
  let p =
    Proof {
      ..ceremony.proof(),
      b: #"a4656cc6c6a28382871372643d056a1c1dcd351b003baeb446d810e04f9e5e2cdd4226a52329e170f56b24c9962081c8170df765c0829b9876886c06965fa2f025ba8b5c46ae867b5b18713d84ab12c42dac34ab2a90e7f20dde6399242f8c4a",
    }
  groth16.verify(p, ceremony.public(), ceremony.verification_key())
}

test adv_tampered_pok() fail {
  let p =
    Proof {
      ..ceremony.proof(),
      pok: #"b10f724272003c500ab3ed8bd34f555b3390028d40933d09b9615aa5a958a4a3b0b813b6fd06324c2c2e74f309d13861",
    }
  groth16.verify(p, ceremony.public(), ceremony.verification_key())
}

test adv_tampered_commitment_compressed() fail {
  let p =
    Proof {
      ..ceremony.proof(),
      commitments: [
        Commitment {
          compressed: #"b942d4cd5004b7b1388d36e91b103439661efe45df162e651b6c573fa580fb82ae04e10e17f4a541d6e7037d2a16532e",
          uncompressed: #"1942d4cd5004b7b1388d36e91b103439661efe45df162e651b6c573fa580fb82ae04e10e17f4a541d6e7037d2a16532d18273eda49573bab4200bc66fe4e34b5867dfc020779f0a4afd6ea5c4a2369dd77acfd9176df5ba16224d3e1293cb5f3",
        },
      ],
    }
  groth16.verify(p, ceremony.public(), ceremony.verification_key())
}

// commitment.uncompressed is NOT decompressed — it is the hash-to-field
// preimage. Tampering it changes the BSB22 challenge, breaking the pairing
// (returns False rather than aborting at decompression).
test rejects_tampered_commitment_uncompressed() {
  let p =
    Proof {
      ..ceremony.proof(),
      commitments: [
        Commitment {
          compressed: #"b942d4cd5004b7b1388d36e91b103439661efe45df162e651b6c573fa580fb82ae04e10e17f4a541d6e7037d2a16532d",
          uncompressed: #"1942d4cd5004b7b1388d36e91b103439661efe45df162e651b6c573fa580fb82ae04e10e17f4a541d6e7037d2a16532d18273eda49573bab4200bc66fe4e34b5867dfc020779f0a4afd6ea5c4a2369dd77acfd9176df5ba16224d3e1293cb5f4",
        },
      ],
    }
  !groth16.verify(p, ceremony.public(), ceremony.verification_key())
}

// ── point-at-infinity rejection ──────────────────────────────────────────────

test adv_point_at_infinity_a() fail {
  let inf = #"c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  groth16.verify(
    Proof { ..ceremony.proof(), a: inf },
    ceremony.public(),
    ceremony.verification_key(),
  )
}

// ── non-canonical / wrong public inputs ──────────────────────────────────────

// A public input >= r (the BLS12-381 scalar field order) is rejected.
test adv_noncanonical_public() fail {
  expect [_first, ..rest] = ceremony.public()
  let r =
    52435875175126190479447740508185965837690552500527637822603658699938581184513
  groth16.verify(ceremony.proof(), [r, ..rest], ceremony.verification_key())
}

test rejects_wrong_public() {
  expect [_first, ..rest] = ceremony.public()
  !groth16.verify(ceremony.proof(), [1, ..rest], ceremony.verification_key())
}

// public-input list length != vk.public_input_count aborts before crypto.
test adv_public_length_mismatch() fail {
  expect [_first, ..rest] = ceremony.public()
  groth16.verify(ceremony.proof(), rest, ceremony.verification_key())
}

// proof commitment count != vk.n_commitments aborts.
test adv_commitment_count_mismatch() fail {
  let p = Proof { ..ceremony.proof(), commitments: [] }
  groth16.verify(p, ceremony.public(), ceremony.verification_key())
}

// ── verification-key shape branches ──────────────────────────────────────────

test vk_shape_rejects_bad_arity() {
  let vk = ceremony.verification_key()
  !groth16.validate_vk_shape(VerificationKey { ..vk, public_input_count: 4 })
}

test vk_shape_rejects_n_commitments_not_one() {
  let vk = ceremony.verification_key()
  !groth16.validate_vk_shape(VerificationKey { ..vk, n_commitments: 2 })
}

test vk_shape_rejects_bad_alpha_length() {
  let vk = ceremony.verification_key()
  !groth16.validate_vk_shape(VerificationKey { ..vk, alpha_g1: #"00" })
}

test vk_shape_rejects_bad_beta_length() {
  let vk = ceremony.verification_key()
  !groth16.validate_vk_shape(VerificationKey { ..vk, beta_g2: #"00" })
}

test vk_shape_rejects_bad_ic_entry() {
  let vk = ceremony.verification_key()
  expect [_ic0, ..ic_rest] = vk.ic
  !groth16.validate_vk_shape(VerificationKey { ..vk, ic: [#"00", ..ic_rest] })
}

test vk_shape_rejects_bad_pedersen_length() {
  let vk = ceremony.verification_key()
  !groth16.validate_vk_shape(VerificationKey { ..vk, pedersen_g: [] })
}

test vk_shape_rejects_negative_public_count() {
  let vk = ceremony.verification_key()
  !groth16.validate_vk_shape(VerificationKey { ..vk, public_input_count: -1 })
}
