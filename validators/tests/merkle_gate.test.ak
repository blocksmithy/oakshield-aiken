use cardano/transaction.{OutputReference}
use cardano/transaction
use merkle/simple
use merkle/simple.{Step}
use merkle_gate
use merkle_gate.{Algo, Blake2b, Datum, Redeemer, Sha256}

// Independent Rust vectors for the 4-leaf tree over "a".."d" (see
// lib/merkle/simple.test.ak).
const b_node_cd: ByteArray =
  #"af66a593dfe7f069b7f3734a87a67df3d87419e270fcf869ab01218e350d3c95"

const b_root4: ByteArray =
  #"421360a6099803b465dff5246cb164c2b6ffac54f17cecc04fa7bfe2561e1804"

const s_node_cd: ByteArray =
  #"dbbd68c325614a73dacb4e7a87a2b7b4ae9724b489e5629ee83151fe8f0eafd7"

const s_root4: ByteArray =
  #"33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0"

const utxo: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

// `algo` is the build-time validator parameter.
fn run(algo: Algo, root: ByteArray, leaf_data: ByteArray, path: List<Step>) -> Bool {
  merkle_gate.merkle_gate.spend(
    algo,
    Some(Datum { root }),
    Redeemer { leaf_data, path },
    utxo,
    transaction.placeholder,
  )
}

// Built for blake2b: prove leaf "a".
test merkle_gate_accepts_blake2b() {
  run(
    Blake2b,
    b_root4,
    "a",
    [
      Step { sibling: simple.leaf_hash(simple.blake2b, "b"), left: False },
      Step { sibling: b_node_cd, left: False },
    ],
  )
}

// Built for sha2-256: same shape, sha2 tree.
test merkle_gate_accepts_sha256() {
  run(
    Sha256,
    s_root4,
    "a",
    [
      Step { sibling: simple.leaf_hash(simple.sha256, "b"), left: False },
      Step { sibling: s_node_cd, left: False },
    ],
  )
}

// A blake2b proof against a script built for sha2-256 is rejected.
test merkle_gate_rejects_algo_mismatch() {
  !run(
    Sha256,
    s_root4,
    "a",
    [
      Step { sibling: simple.leaf_hash(simple.blake2b, "b"), left: False },
      Step { sibling: b_node_cd, left: False },
    ],
  )
}

// Non-member leaf is rejected.
test merkle_gate_rejects_non_member() {
  !run(
    Blake2b,
    b_root4,
    "x",
    [
      Step { sibling: simple.leaf_hash(simple.blake2b, "b"), left: False },
      Step { sibling: b_node_cd, left: False },
    ],
  )
}

// The leaf is domain-separated, so leaf_data = root with an empty path is rejected.
test merkle_gate_rejects_empty_path_root_as_leaf() {
  !run(Blake2b, b_root4, b_root4, [])
}
