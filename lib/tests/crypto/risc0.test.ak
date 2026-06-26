//// Native (`risc0-groth16-bls`) tests for [crypto/risc0](./risc0.html), against
//// the production `small-ceremony-2026-06` fixture in [dev/ceremony](../dev/ceremony.html).

use crypto/risc0.{Risc0Params}
use crypto/risc0
use dev/ceremony

// The committed journal + pinned image_id reproduce the expected ReceiptClaim digest.
test claim_digest_matches_oracle() {
  risc0.claim_digest(ceremony.journal, ceremony.image_id) == ceremony.expected_claim_digest
}

// lift_to_scalars derives exactly the 5 native BLS12-381 Fr public inputs.
test lift_to_scalars_matches_public() {
  risc0.lift_to_scalars(ceremony.journal, ceremony.risc0_params()) == ceremony.public()
}

// verify_receipt: one-call lift + verify of the production proof.
test verify_receipt_accepts_production() {
  risc0.verify_receipt(
    ceremony.verification_key(),
    ceremony.risc0_params(),
    ceremony.proof(),
    ceremony.journal,
  )
}

// A proof bound to a different journal must not verify (the derived claim digest,
// hence the public inputs, change → pairing fails).
test verify_receipt_rejects_wrong_journal() {
  !risc0.verify_receipt(
    ceremony.verification_key(),
    ceremony.risc0_params(),
    ceremony.proof(),
    #"8801000000000000",
  )
}

// A wrong-length image_id aborts in lift_to_scalars (the param-shape check),
// rather than silently producing a wrong claim digest.
test lift_to_scalars_rejects_short_image_id() fail {
  let p = Risc0Params { ..ceremony.risc0_params(), image_id: #"00" }
  risc0.lift_to_scalars(ceremony.journal, p) == ceremony.public()
}
