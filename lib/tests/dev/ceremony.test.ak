//// Pins the production VK hash. The ceremony fixture's proof acceptance,
//// journal binding, and tamper rejection are exercised in
//// [crypto/groth16](../crypto/groth16.html) and [crypto/risc0](../crypto/risc0.html).

use aiken/builtin
use dev/ceremony

// The verifying key hashes to the pinned ceremony value (the off-chain
// RISC0_GROTH16_BLS_VK_SHA256 gate).
test vk_pin_matches() {
  builtin.sha2_256(ceremony.vk_raw) == ceremony.vk_sha256
}
