use merkle/simple
use merkle/simple.{Step}

// Known-answer vectors from an INDEPENDENT Rust implementation (blake2 / sha2
// crates, not the Aiken builtins under test), for the 4-leaf tree over "a".."d"
// with leaf = hash(0x00 ‖ data), node = hash(0x01 ‖ left ‖ right):
//   root = node( node(leaf a, leaf b), node(leaf c, leaf d) )

// ── blake2b ──────────────────────────────────────────────────────────────────

const b_leaf_a: ByteArray =
  #"7234082e1dd0b5ec0acd71875d61c9f374af30c100bc4de7aa4eb3f15bbed686"

const b_node_ab: ByteArray =
  #"ee616625a590167bc4b3dc703ab4f3f2ddecbee6b9d05fee9281f02046e6082e"

const b_node_cd: ByteArray =
  #"af66a593dfe7f069b7f3734a87a67df3d87419e270fcf869ab01218e350d3c95"

const b_root4: ByteArray =
  #"421360a6099803b465dff5246cb164c2b6ffac54f17cecc04fa7bfe2561e1804"

// ── sha2-256 ─────────────────────────────────────────────────────────────────

const s_node_cd: ByteArray =
  #"dbbd68c325614a73dacb4e7a87a2b7b4ae9724b489e5629ee83151fe8f0eafd7"

const s_root4: ByteArray =
  #"33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0"

// leaf_hash matches the independent oracle for each algorithm.
test blake2b_leaf_hash_known_answer() {
  simple.leaf_hash(simple.blake2b, "a") == b_leaf_a
}

// Reconstruct the blake2b root from leaf a + its literal siblings.
test blake2b_includes() {
  simple.includes(
    simple.blake2b,
    b_root4,
    "a",
    [
      Step { sibling: simple.leaf_hash(simple.blake2b, "b"), left: False },
      Step { sibling: b_node_cd, left: False },
    ],
  )
}

// The SAME path and leaves under sha2-256 reconstruct the sha2-256 root.
test sha256_includes() {
  simple.includes(
    simple.sha256,
    s_root4,
    "a",
    [
      Step { sibling: simple.leaf_hash(simple.sha256, "b"), left: False },
      Step { sibling: s_node_cd, left: False },
    ],
  )
}

// The two algorithms are genuinely different — a blake2b proof must NOT verify
// against the sha2-256 root (and the roots differ).
test algorithms_are_distinct() {
  and {
    b_root4 != s_root4,
    !simple.includes(
      simple.sha256,
      s_root4,
      "a",
      [
        Step { sibling: simple.leaf_hash(simple.blake2b, "b"), left: False },
        Step { sibling: b_node_cd, left: False },
      ],
    ),
  }
}

// Wrong sibling side → not included (blake2b).
test rejects_wrong_side() {
  !simple.includes(
    simple.blake2b,
    b_root4,
    "a",
    [
      Step { sibling: simple.leaf_hash(simple.blake2b, "b"), left: True },
      Step { sibling: b_node_cd, left: False },
    ],
  )
}

// Domain separation: a leaf-tagged hash of "a"‖"b" is not the node of leaf a,b.
test leaf_node_domain_separated() {
  simple.leaf_hash(simple.blake2b, "ab") != b_node_ab
}

// A spender cannot bypass with leaf_data = root and an empty path: includes
// domain-separates the leaf, so leaf_hash(root) can never equal a node root.
test rejects_empty_path_root_as_leaf() {
  !simple.includes(simple.blake2b, b_root4, b_root4, [])
}

// Accept path through a left-sibling step: leaf "b" is the right child at
// level 0, so its sibling (leaf "a") is on the left.
test includes_left_sibling() {
  simple.includes(
    simple.blake2b,
    b_root4,
    "b",
    [
      Step { sibling: b_leaf_a, left: True },
      Step { sibling: b_node_cd, left: False },
    ],
  )
}
