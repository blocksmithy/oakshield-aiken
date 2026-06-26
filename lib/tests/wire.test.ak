use aiken/primitive/bytearray
use dev/ceremony
use crypto/groth16
use crypto/risc0
use wire

// Decoders round-trip the production ceremony fixtures to the same structured
// values that were hand-parsed in `ceremony.ak`.

test parse_vk_roundtrip() {
  wire.parse_vk(ceremony.vk_raw) == ceremony.verification_key()
}

test parse_proof_roundtrip() {
  wire.parse_proof(ceremony.proof_raw) == ceremony.proof()
}

test parse_public_roundtrip() {
  wire.parse_public(ceremony.public_raw) == ceremony.public()
}

// End-to-end straight from wire bytes: parse everything, then verify.
test verify_from_wire_bytes() {
  let vk = wire.parse_vk(ceremony.vk_raw)
  let proof = wire.parse_proof(ceremony.proof_raw)
  let public = wire.parse_public(ceremony.public_raw)
  and {
    public == risc0.lift_to_scalars(ceremony.journal, ceremony.risc0_params()),
    groth16.verify(proof, public, vk),
  }
}

// ── negative paths ───────────────────────────────────────────────────────────

// The VK-shape guard: a VK whose commitment commits a public wire (committed
// count 1 instead of 0) is rejected. Replaces the trailing 4-byte committed
// section (count 0) with count 1 + one index.
test parse_vk_rejects_committed_wire() fail {
  let n = bytearray.length(ceremony.vk_raw)
  let crafted =
    bytearray.concat(bytearray.take(ceremony.vk_raw, n - 4), #"0000000100000000")
  wire.parse_vk(crafted).n_commitments == 1
}

// An extra trailing byte breaks the exact-consumption check (off3 == length).
test parse_vk_rejects_trailing_bytes() fail {
  wire.parse_vk(bytearray.concat(ceremony.vk_raw, #"00")).n_commitments == 1
}

// parse_public is native-only: n_limbs != 1 is rejected.
test parse_public_rejects_wrong_n_limbs() fail {
  let crafted =
    bytearray.concat(#"0000000500000002", bytearray.drop(ceremony.public_raw, 8))
  wire.parse_public(crafted) == ceremony.public()
}
