use cardano/nullifier
use dev/testkit

const empty_root: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

const k1: ByteArray =
  #"1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b"

const k2: ByteArray =
  #"9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f503"

// The testkit-generated MPF proof is accepted by the on-chain
// insert: first insert k1 into the empty set, then k2 into {k1}
// using a freshly-built absence proof for k2. If either insert's
// internal exclusion check rejected, the chain would `fail` before
// the final assertion. Reaching the comparison proves both proofs
// were valid + the resulting root differs from the single-element
// root.
test mpf_insert_proof_is_valid() {
  let s1 = nullifier.spend(empty_root, k1, [])
  let s2 = nullifier.spend(s1, k2, testkit.mpf_insert_proof(k1, k2))
  s2 != s1
}
