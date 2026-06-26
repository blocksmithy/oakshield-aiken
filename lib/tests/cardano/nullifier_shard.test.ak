use aiken/primitive/bytearray
use cardano/nullifier
use cardano/nullifier_shard

const k1: ByteArray =
  #"1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b"

// 0x1d = 29; 29 % 16 = 13.
test shard_of_known() {
  nullifier_shard.shard_of(k1, 16) == 13
}

test in_shard_matches() {
  and {
    nullifier_shard.in_shard(k1, 16, 13),
    !nullifier_shard.in_shard(k1, 16, 0),
  }
}

// derive matches an independent Rust-blake2 computation of
// blake2b_256("tx" ‖ k1) — catches a wrong hash or concat order.
test derive_known_answer() {
  nullifier.derive("tx", k1) == #"714452e94070c26cb3ad1d9891cf36b7ec563f27e93ad2156b18b8b9dab8f353"
}

test derive_domain_separated() {
  nullifier.derive("a", k1) != nullifier.derive("b", k1)
}

test derive_value_separated() {
  let k2 = bytearray.concat(#"00", bytearray.drop(k1, 1))
  nullifier.derive("tx", k1) != nullifier.derive("tx", k2)
}
