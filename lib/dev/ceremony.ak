//// Production ceremony fixture: `small-ceremony-2026-06`.
////
//// A real `identity_bls` hello-world receipt (proves knowledge of two factors
//// of 391 and commits the product) proved under the PRODUCTION ceremony
//// verifying key, in the Cardano wire format. Parsed from the hand-over
//// package's `vk/proof/public/journal.cardano.bin`.
////
//// Test-only — not imported by any validator, so it is dead-code-eliminated
//// from `plutus.json`.

use aiken/primitive/bytearray
use crypto/groth16.{Commitment, Proof, VerificationKey}
use crypto/risc0.{Risc0Params}

// ── pinned identity ─────────────────────────────────────────────────────────

/// `sha256(vk.cardano.bin)` — the value to pin on-chain (= the off-chain
/// `RISC0_GROTH16_BLS_VK_SHA256` gate).
pub const vk_sha256: ByteArray =
  #"7db98ea2d19b86853dee0a076141f51fadabf1ace22b2e6c86822947101355a5"

/// Guest image id (`MULTIPLY_ID`).
pub const image_id: ByteArray =
  #"0a795143150ea5c309a517ac6ffe3b7f04ea301af59d1ce16624199b335adb30"

/// The guest's committed journal: `u64 LE 391`.
pub const journal: ByteArray = #"8701000000000000"

/// Allowed inner-recursion control root (platform constant).
pub const control_root: ByteArray =
  #"a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56"

/// `identity_bls` program control id (platform constant, as raw bytes).
pub const bls_identity_control_id: ByteArray =
  #"5b53e73e4d7c7a440567053460d07f582c62b6b9dafd1cb6e116092068409368"

/// Expected `claim_digest` for (image_id, journal, Halted(0)).
pub const expected_claim_digest: ByteArray =
  #"3f1c5494cd84eea3a838deac555830b4128a7ad2834357b2498ae04718f16692"

// ── raw wire bytes (for the VK pin + tamper round-trip) ─────────────────────

pub const vk_raw: ByteArray =
  #"98a2f427212c1c111ba213051cff7819f732620d2dfc70dab8fe631811751ada13c91ec947aa74c4c1c5b95d2213f919af0bc2cee6cfa46a2814fb2cbf0fe71ae61f990affcf94ecd926e94805b8a9eaf04ccc89b8d20baab4e02e2eac9bcbc712b393384039102802f8b53ec56421f98c19cd908d9b2e74c70a33261579e16b52fc271444c9ff25114bb15af6d0ecda93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8b470c773234e18887bd1165a70c87e65ecbdfb2327b65ec6380b965450dba3ef68f7b67276a1a85b206c3abb543ca9230e6764ca4fb428376a45aa33905c7300ab9a2ce6280f89f74af9e46e1b43ddd7fa1a3383356e125a744333fce2cbfbec000000078cad8e9862c80cc268740ad3817d96013722c626b26a7686672f36e217c9d40d56077fe55305855905ec2d059b3ceb1ab667202fabad92b7c88e9001c9c4339a5b66c3b06713f7d7d365ebcaa6ab5eadba589bdaa3ccfad412ad0b1d1caac019b244a4d8f8dfa55bafafd954381549f8ce0e692eb42abe36480fc30dc83d49edaeed901c4c57f9fb0e9a6504f240adc5a055072df7e2346bf3c39959165e2850d5346f3a9d7f54d5fde76c003edd96b96b01842469d9aabd566d8b4d509bbf5492c17c05dbcb7125fba004bdb8f20b4ef421466c6b751ec091f1951ec919556be61845bc12b7c26d0871b11850e1b4e3b98953bb31b06b413ead0ad797841ef55100843b0358f05a12e4f22a1af7e25c7b348e31202d2ff36014387c3b294a4c96e4407428f38c0a026417b39fab66f86145789dcb784b950751dd80344683dbb03ddb8d1c4d5e8abb152579494aa40f0000000193e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb88392ddfaab36cbb01eafde83bdea87147f96aba17331ffe6b5e73a849f162f9006d4bfa3017a0dba6a312fbad87e51831547f497e0426d557437711a39eeef3e95e80933fa2af1a125b9a8eb9d4475d90d522e59fe4e1c6bac864b114bc13bbc00000000"

pub const proof_raw: ByteArray =
  #"a9f7cbf487c8bb500a5f405fa576edbc1deba56da1d945b9530bb4a8f84185927b82ff9fcf97ee5195692ca62e4e4bc7a4656cc6c6a28382871372643d056a1c1dcd351b003baeb446d810e04f9e5e2cdd4226a52329e170f56b24c9962081c8170df765c0829b9876886c06965fa2f025ba8b5c46ae867b5b18713d84ab12c42dac34ab2a90e7f20dde6399242f8c498959414e0bf0ee8596eac8ed999f290fc62cc21e65aec35ba4ed50ea3628dfd6d0fec0cd65991bdb061219a62de4367e00000001b942d4cd5004b7b1388d36e91b103439661efe45df162e651b6c573fa580fb82ae04e10e17f4a541d6e7037d2a16532d1942d4cd5004b7b1388d36e91b103439661efe45df162e651b6c573fa580fb82ae04e10e17f4a541d6e7037d2a16532d18273eda49573bab4200bc66fe4e34b5867dfc020779f0a4afd6ea5c4a2369dd77acfd9176df5ba16224d3e1293cb5f3b10f724272003c500ab3ed8bd34f555b3390028d40933d09b9615aa5a958a4a3b0b813b6fd06324c2c2e74f309d13860"

pub const public_raw: ByteArray =
  #"00000005000000010000000000000000000000000000000041af18736dc9d7921c859fc95ac84da500000000000000000000000000000000561f8c992a424deb37ccdf4e19c0e7db00000000000000000000000000000000b4305855acde38a8a3ee84cd94541c3f000000000000000000000000000000009266f11847e08a49b2574383d27a8a1268934068200916e1b61cfddab9b6622c587fd06034056705447a7c4d3ee7535b"

// ── parsed verifying key ────────────────────────────────────────────────────

pub fn verification_key() -> VerificationKey {
  VerificationKey {
    alpha_g1: #"98a2f427212c1c111ba213051cff7819f732620d2dfc70dab8fe631811751ada13c91ec947aa74c4c1c5b95d2213f919",
    beta_g2: #"af0bc2cee6cfa46a2814fb2cbf0fe71ae61f990affcf94ecd926e94805b8a9eaf04ccc89b8d20baab4e02e2eac9bcbc712b393384039102802f8b53ec56421f98c19cd908d9b2e74c70a33261579e16b52fc271444c9ff25114bb15af6d0ecda",
    gamma_g2: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
    delta_g2: #"b470c773234e18887bd1165a70c87e65ecbdfb2327b65ec6380b965450dba3ef68f7b67276a1a85b206c3abb543ca9230e6764ca4fb428376a45aa33905c7300ab9a2ce6280f89f74af9e46e1b43ddd7fa1a3383356e125a744333fce2cbfbec",
    ic: [
      #"8cad8e9862c80cc268740ad3817d96013722c626b26a7686672f36e217c9d40d56077fe55305855905ec2d059b3ceb1a",
      #"b667202fabad92b7c88e9001c9c4339a5b66c3b06713f7d7d365ebcaa6ab5eadba589bdaa3ccfad412ad0b1d1caac019",
      #"b244a4d8f8dfa55bafafd954381549f8ce0e692eb42abe36480fc30dc83d49edaeed901c4c57f9fb0e9a6504f240adc5",
      #"a055072df7e2346bf3c39959165e2850d5346f3a9d7f54d5fde76c003edd96b96b01842469d9aabd566d8b4d509bbf54",
      #"92c17c05dbcb7125fba004bdb8f20b4ef421466c6b751ec091f1951ec919556be61845bc12b7c26d0871b11850e1b4e3",
      #"b98953bb31b06b413ead0ad797841ef55100843b0358f05a12e4f22a1af7e25c7b348e31202d2ff36014387c3b294a4c",
      #"96e4407428f38c0a026417b39fab66f86145789dcb784b950751dd80344683dbb03ddb8d1c4d5e8abb152579494aa40f",
    ],
    pedersen_g: [
      #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
    ],
    pedersen_g_sigma_neg: [
      #"8392ddfaab36cbb01eafde83bdea87147f96aba17331ffe6b5e73a849f162f9006d4bfa3017a0dba6a312fbad87e51831547f497e0426d557437711a39eeef3e95e80933fa2af1a125b9a8eb9d4475d90d522e59fe4e1c6bac864b114bc13bbc",
    ],
    n_commitments: 1,
    public_input_count: 5,
  }
}

// ── parsed proof ────────────────────────────────────────────────────────────

pub fn proof() -> Proof {
  Proof {
    a: #"a9f7cbf487c8bb500a5f405fa576edbc1deba56da1d945b9530bb4a8f84185927b82ff9fcf97ee5195692ca62e4e4bc7",
    b: #"a4656cc6c6a28382871372643d056a1c1dcd351b003baeb446d810e04f9e5e2cdd4226a52329e170f56b24c9962081c8170df765c0829b9876886c06965fa2f025ba8b5c46ae867b5b18713d84ab12c42dac34ab2a90e7f20dde6399242f8c49",
    c: #"8959414e0bf0ee8596eac8ed999f290fc62cc21e65aec35ba4ed50ea3628dfd6d0fec0cd65991bdb061219a62de4367e",
    commitments: [
      Commitment {
        compressed: #"b942d4cd5004b7b1388d36e91b103439661efe45df162e651b6c573fa580fb82ae04e10e17f4a541d6e7037d2a16532d",
        uncompressed: #"1942d4cd5004b7b1388d36e91b103439661efe45df162e651b6c573fa580fb82ae04e10e17f4a541d6e7037d2a16532d18273eda49573bab4200bc66fe4e34b5867dfc020779f0a4afd6ea5c4a2369dd77acfd9176df5ba16224d3e1293cb5f3",
      },
    ],
    pok: #"b10f724272003c500ab3ed8bd34f555b3390028d40933d09b9615aa5a958a4a3b0b813b6fd06324c2c2e74f309d13860",
  }
}

// ── public inputs (5 native scalars, read big-endian) ───────────────────────

pub fn public() -> List<Int> {
  [
    bytearray.to_int_big_endian(
      #"0000000000000000000000000000000041af18736dc9d7921c859fc95ac84da5",
    ),
    bytearray.to_int_big_endian(
      #"00000000000000000000000000000000561f8c992a424deb37ccdf4e19c0e7db",
    ),
    bytearray.to_int_big_endian(
      #"00000000000000000000000000000000b4305855acde38a8a3ee84cd94541c3f",
    ),
    bytearray.to_int_big_endian(
      #"000000000000000000000000000000009266f11847e08a49b2574383d27a8a12",
    ),
    bytearray.to_int_big_endian(
      #"68934068200916e1b61cfddab9b6622c587fd06034056705447a7c4d3ee7535b",
    ),
  ]
}

/// RISC0 platform parameters for this proof. `control_id_fr` is the
/// `BLS_IDENTITY_CONTROL_ID` read as an Fr (`from_be(reverse(bytes))` = LE).
pub fn risc0_params() -> Risc0Params {
  Risc0Params {
    image_id,
    control_root,
    control_id_fr: bytearray.to_int_little_endian(bls_identity_control_id),
  }
}
