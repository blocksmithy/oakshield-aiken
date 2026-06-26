//// Generic binary Merkle-tree inclusion proofs with a **pluggable** hash.
////
//// The hash function is passed in as a [Hasher](#Hasher), so the same logic
//// works over `blake2b_256` or `sha2_256` (or any 32-byte hash). Leaves and
//// internal nodes are domain separated (RFC 6962 style): a leaf is
//// `hash(0x00 ‖ data)` and an internal node is `hash(0x01 ‖ left ‖ right)`.
//// The tag makes a leaf and a node provably distinct, so `includes` is safe
//// even with an attacker-supplied path (no second-preimage between levels).
////
//// ```aiken
//// use merkle/simple
//// let ok = simple.includes(simple.blake2b, root, leaf_data, path)   // or simple.sha256
//// ```

use aiken/builtin
use aiken/primitive/bytearray

/// A 32-byte hash function. Use [blake2b](#blake2b) or [sha256](#sha256), or
/// supply your own.
pub type Hasher =
  fn(ByteArray) -> ByteArray

/// The `blake2b_256` hasher.
pub fn blake2b(input: ByteArray) -> ByteArray {
  builtin.blake2b_256(input)
}

/// The `sha2_256` hasher.
pub fn sha256(input: ByteArray) -> ByteArray {
  builtin.sha2_256(input)
}

const leaf_tag: ByteArray = #"00"

const node_tag: ByteArray = #"01"

/// One step on the path from a leaf to the root: a sibling node and its side.
pub type Step {
  /// The sibling node hash at this level.
  sibling: ByteArray,
  /// `True` if the sibling is on the left (`node(sibling, current)`),
  /// `False` if on the right (`node(current, sibling)`).
  left: Bool,
}

/// Hash a leaf's contents into a (domain-separated) leaf node:
/// `hash(0x00 ‖ data)`. Build leaves with this so a leaf can never collide
/// with an internal node.
pub fn leaf_hash(hash: Hasher, data: ByteArray) -> ByteArray {
  hash(bytearray.concat(leaf_tag, data))
}

/// Recompute the Merkle root from a leaf node and its sibling path, using
/// `hash` at every level.
pub fn root_from(hash: Hasher, leaf: ByteArray, path: List<Step>) -> ByteArray {
  when path is {
    [] -> leaf
    [Step { sibling, left }, ..rest] -> {
      let parent =
        if left {
          node(hash, sibling, leaf)
        } else {
          node(hash, leaf, sibling)
        }
      root_from(hash, parent, rest)
    }
  }
}

/// True iff a leaf with raw contents `leaf_data` is included under `root` via
/// `path`, hashing with `hash`. The leaf is domain-separated internally with
/// [leaf_hash](#leaf_hash), so this is safe with an attacker-supplied
/// `leaf_data` and `path`: a leaf can never equal an internal node, and an empty
/// path only matches when `leaf_hash(leaf_data) == root` (a single-leaf tree).
/// For a proof over an already-hashed leaf node, use [root_from](#root_from).
pub fn includes(
  hash: Hasher,
  root: ByteArray,
  leaf_data: ByteArray,
  path: List<Step>,
) -> Bool {
  root_from(hash, leaf_hash(hash, leaf_data), path) == root
}

// Internal node: `hash(0x01 ‖ left ‖ right)`.
fn node(hash: Hasher, left: ByteArray, right: ByteArray) -> ByteArray {
  hash(node_tag |> bytearray.concat(left) |> bytearray.concat(right))
}
