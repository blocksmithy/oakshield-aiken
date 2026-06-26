//// SHA-256 incremental Merkle tree (IMT) inclusion verification, depth 40.
//// Designed for the `oaks_txtree` proof variant: a RISC0 Groth16 proof
//// re-expresses the Mithril Blake2s tx-merkle as a SHA-256 tree whose root `Y`
//// is published on chain. SHA-256-only inclusion proofs verify against that
//// pre-bound `Y`, amortising the one-time SNARK cost across many downstream
//// inclusion calls.
////
//// Spec (domain-separated leaf / node / anchor; v1/v2 dispatched implicitly by
//// `block_le8` length):
////
//// ```text
//// leaf_v1    = sha256(0x00 ‖ txid)                                 // block_le8 = #""
//// leaf_v2    = sha256(0x00 ‖ txid ‖ block_number_LE8 ‖ slot_LE8)   // block_le8 = 8 B
//// node       = sha256(0x01 ‖ left ‖ right)
//// anchor     = sha256(0x03 ‖ x_start)                              // leaf 0 only
//// zeros[0]   = 32 × 0x00
//// zeros[k]   = sha256(0x01 ‖ zeros[k-1] ‖ zeros[k-1])              // k = 1 .. 40
//// Y          = depth-40 tree, empty slots padded with zeros[k]
//// ```
////
//// **Soundness — domain separation + length pins.** The `0x00`/`0x01`/`0x03`
//// prefixes make a leaf, node, and anchor hash provably distinct regardless of
//// input length: a single, self-contained guarantee against leaf-vs-node
//// second preimages. The length pins in `verify_inclusion` (txid 32 B,
//// block/slot ∈ {0,8}, every sibling 32 B) are belt-and-suspenders. A
//// prefix-free variant is sound for this fixed-depth shape under the length
//// pins alone (the Ethereum SSZ construction), but the prefixes cost ~one byte
//// per hash and buy a guarantee that doesn't hinge on every pin holding, so
//// they stay.
////
//// **Wire shape — caller pre-expands compressed proofs.** Callers supply the 40
//// siblings as a raw `List<ByteArray>`; off-chain substitution of `zeros[k]`
//// for empty branches happens before tx submission. The on-chain validator
//// never references the `zeros[]` table; it is kept `pub` for off-chain
//// expanders.
////
//// Inclusion is verified by reconstructing the leaf, then walking 40 levels
//// combining with siblings: `(idx >> k) & 1 == 0` means the current node is the
//// LEFT child at level k, so the sibling is on the right. ACCEPT iff the
//// reconstructed root equals the on-chain-pinned `Y`.
////
//// `verify_inclusion` is curve-agnostic and stateless; a downstream validator
//// reads `Y` from the y-token's datum and calls this for any (txid, proof).
//// Cost: 41 SHA-256 calls (leaf + 40 levels), ≈ 0.5 B CPU / 1.7 M mem per
//// inclusion check — small beside the pairing it amortises.

use aiken/builtin
use aiken/collection/list
use aiken/primitive/bytearray

/// Tree depth — fixed by the spec at 40 (≈ 1 trillion leaves).
pub const tree_depth: Int = 40

/// 41 zero-subtree roots, level 0 (empty leaf) through level 40 (empty root).
/// Off-chain proof expanders point at these to substitute for empty branches
/// before tx submission; the on-chain verifier walks the pre-expanded sibling
/// list and never reads this table. Domain-separated recipe:
///   `zeros[0] = 32 × 0x00`, `zeros[k] = sha256(0x01 ‖ zeros[k-1] ‖ zeros[k-1])`.
/// `zeros[40]` = `56530aa5d958fb0a…cb06a5e4` (empty-tree root at depth 40).
pub const zeros: List<ByteArray> =
  [
    #"0000000000000000000000000000000000000000000000000000000000000000",
    #"ae0798d0ecaed2b778eddebf18f071a561c53658c05e76cedecc27cafbdbc577",
    #"90534fe0aff6db9edb29eee74e78a386916a581c8e6465349493e1a6c87241e1",
    #"bea16162721bca4b6e1782cbdc695a471522157c6716f508db47c599195340f4",
    #"30765fef341bdfe749c391bf956a9f03d363941b2eb8f85ab16bb6eb0d3c4def",
    #"f1a0a71a6550c41bc8d4dac4f186b6d274a839f2f95ad9e3bb651d45810c5a1f",
    #"c6984907d2e534964351393bc85f04374065b63870cc859c68192def090c1017",
    #"dc0606b906238dd157e69cb261e75696007e4d9a3f707a7ce10ce410d08bcfec",
    #"8e4b3745e5f2f7d48e36b192cb39242fa0f7a76fac1e36a519d8ebe00f3e21fb",
    #"bd752b8e76f5f891e5d3a10352dbf3ac25123b6eb48a3ad154020cd0c84d2176",
    #"29398d48e1a1a9f3c8e0f97b0f8c066d2beaf88a319baef02a5482d6157ebd2b",
    #"76dc94f187362590f6fd2f1e2b1b8c8f06d7439080b4a499ae6b267ab1b5cc31",
    #"d100399f607ba956d68737045ea9eb3e75475dfa633b7cabecf0afa05c9f3af8",
    #"3e46222c092b9baa5a16df1dc2864c7cb5fb79609d096ac2a10d64f824d1c73a",
    #"8cf2c9bd2369a3b9e0bbdd2cee634605440adb2d70b15263dbe7d0d16ebfc03d",
    #"fbbb942587ef256738d2bbb0506423880206cfbfa2ed4d340d796b0f7e290980",
    #"bbc84bb1eca9b98b546708cadcf829983dd03da168f65aeae21724003072c21a",
    #"669b03f8ec7153d9f9db779449f504489942359aab734d938417889394394b09",
    #"a3f6714a23c8f9b91fb3dd6e311bd1cf5f8bcb3618dee8ae5cd7ab0ec40c0876",
    #"0bd2118fbd68fa6bb6733596bb879f571bd648821f7437419dcf49f5078f1db8",
    #"51c20d66008024c04cf114564a998e49ef8f6e044e2d13a03a66521d6e200503",
    #"b29e665a5be928c888cae79638ea9f6febb5e0da9c0adb8eef892895fdeb34f3",
    #"e39d25ebb3238dd9c246e22cceeffe7a6def739037e7ddb41889d3ed2bdb54cb",
    #"c39d9328c5e0bef02e859ce63d15d3a5240a4c52ee34bb87ac5ba231910bf5f0",
    #"fd153e6be1763177c1d43f43661a359214d26256cf62b811d8442382dbca7470",
    #"e8123d755c5a32140ea87605c18ef7f342dc7461e1fd470a158356eaed68503d",
    #"16022e1fc087982698d7861ece2506bc8f21626c03a30c424259d3f7fde28633",
    #"655542f14a719ca624255c59096d3afb83ccef5bb29ce05d37d540e939a3d7d1",
    #"259debd0f2289401c7da9aeb0057abb1d4a8c7a2cffe0af3ec42910497936a75",
    #"dd363ae2d13611d37dac77e653436745bcda1f4e2d76b04b2723930947d94602",
    #"5a62aaa41541242cf12e482743eedf403c08e920330f6736825bfe27f2da8237",
    #"e69e674ae78b120925d53f10daccf990ddd831c025415bdf41b4d594157d23cf",
    #"782d35b1fdad7d54e7a1b36a2ab1021e872c7692bb80fdd12bfc321e9e420409",
    #"c8f9772c21b75d40eb91db7a570f51da2565f462325429f0b2687396375b2194",
    #"0ca8d2f477d64216c4d57606136dd9af5e14b3d447277080d8a01f008dc49117",
    #"c4dd00653db03c32387451558e7dece55ce3cd3b179642ccb6aa6dddf0a76e9c",
    #"a1e8ec6d2d2be573b103372312d3fd8668ec473ddc9172966f3a1522b5f8916b",
    #"f84c6ec46a6ba8f898203e2ba508fa4d61fb3b8acabf426a13ac411567f0bdc6",
    #"16a5d7129551c06e0c5fb541c8413c9d975856e6c63d63860dfa4849229f39db",
    #"14c2f6d6ca2c6dc42acb33207e130371b5c4d4388a324cf1e3bb33ac597b0b50",
    #"56530aa5d958fb0a28d5dbaa6c2a2d3857e93c43faaf60265b59159ccb06a5e4",
  ]

const leaf_tag: ByteArray = #"00"

const node_tag: ByteArray = #"01"

const anchor_tag: ByteArray = #"03"

/// `node = sha256(0x01 ‖ left ‖ right)`.
fn node_hash(left: ByteArray, right: ByteArray) -> ByteArray {
  builtin.sha2_256(node_tag |> bytearray.concat(left) |> bytearray.concat(right))
}

/// Reconstruct the leaf hash `sha256(0x00 ‖ txid [‖ block_le8 ‖ slot_le8])`.
///
/// Version is implicit in `block_le8` length:
///   - `block_le8 = #""` (length 0)        → v1 leaf = sha256(0x00 ‖ txid)
///   - `block_le8 = 8-byte LE block_number` → v2 leaf = sha256(0x00 ‖ txid ‖ block_le8 ‖ slot_le8)
///
/// `slot_le8` MUST be `#""` iff `block_le8 = #""`; otherwise MUST be 8 B.
/// `verify_inclusion` enforces these length pins before calling.
pub fn leaf_hash(
  txid: ByteArray,
  block_le8: ByteArray,
  slot_le8: ByteArray,
) -> ByteArray {
  builtin.sha2_256(
    leaf_tag
      |> bytearray.concat(txid)
      |> bytearray.concat(block_le8)
      |> bytearray.concat(slot_le8),
  )
}

/// `anchor = sha256(0x03 ‖ x_start)` — populates leaf slot 0 of every y-trail.
/// `verify_inclusion` itself doesn't read x_start (callers don't pass it); this
/// helper is exposed for tests + for downstream contracts that want to derive
/// the anchor for inspection.
pub fn anchor_hash(x_start: ByteArray) -> ByteArray {
  builtin.sha2_256(bytearray.concat(anchor_tag, x_start))
}

/// Walk 40 levels combining `cur` with each sibling. At level `k`,
/// `(idx >> k) & 1 == 0` means `cur` is the LEFT child (sibling is on the
/// right); else `cur` is the RIGHT child (sibling on the left).
fn walk(cur: ByteArray, idx: Int, siblings: List<ByteArray>) -> ByteArray {
  when siblings is {
    [] -> cur
    [sib, ..rest] -> {
      let next =
        if idx % 2 == 0 {
          node_hash(cur, sib)
        } else {
          node_hash(sib, cur)
        }
      walk(next, idx / 2, rest)
    }
  }
}

/// Verify that `(txid, block_le8, slot_le8)` is at slot `leaf_index` of the
/// depth-40 SHA-256 IMT rooted at `y_root`. Returns `True` iff the reconstructed
/// root matches `y_root`.
///
/// Wire-shape pins enforced before the walk:
///   - `siblings` length == 40 (tree depth), and every sibling is 32 B
///   - `leaf_index` in `[0, 2^40)`
///   - `txid` length == 32 B
///   - `block_le8` length ∈ {0, 8}; `slot_le8` matched (both 0 → v1; both 8 → v2;
///     mixed → reject)
///
/// EU cost ≈ 41 SHA-256 calls + plumbing ≈ 0.5 B CPU / 1.7 M mem.
pub fn verify_inclusion(
  y_root: ByteArray,
  txid: ByteArray,
  block_le8: ByteArray,
  slot_le8: ByteArray,
  leaf_index: Int,
  siblings: List<ByteArray>,
) -> Bool {
  // Tree depth is fixed; reject malformed proofs before the walk.
  expect list.length(siblings) == tree_depth
  // Every sibling is a 32-byte node hash: pins node inputs to 64 B so the
  // domain-separated structure holds (and keeps the no-prefix variant sound too).
  expect list.all(siblings, fn(s) { bytearray.length(s) == 32 })
  expect leaf_index >= 0
  expect leaf_index < 1099511627776
  // ^ 2^40 — keeps the index in the legal range; the modular bit-walk in `walk`
  // would silently accept overflow otherwise.

  // Wire pins. txid is always 32 B (Mithril tx hash). v1 dispatch = both
  // length-suffix fields empty; v2 dispatch = both 8-byte LE. Any other
  // combination is malformed.
  expect bytearray.length(txid) == 32
  let block_len = bytearray.length(block_le8)
  let slot_len = bytearray.length(slot_le8)
  expect or {
    and {
      block_len == 0,
      slot_len == 0,
    },
    and {
      block_len == 8,
      slot_len == 8,
    },
  }

  let leaf = leaf_hash(txid, block_le8, slot_le8)
  let reconstructed = walk(leaf, leaf_index, siblings)
  reconstructed == y_root
}
