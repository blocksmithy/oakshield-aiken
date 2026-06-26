//// Example: unlock if a leaf is included under a committed Merkle root.
////
//// The hash algorithm is a build-time choice: it's a validator parameter, so
//// each deployment compiles to one script fixed to blake2b-256 or sha2-256
//// (distinct script hashes). The datum holds the root; the redeemer carries the
//// raw leaf data and its sibling path. `simple.includes` domain-separates the
//// leaf internally, so an empty path can't be passed off as the root.
//// Demonstrates [merkle/simple](../lib/merkle/simple.html), whose hash is
//// selected at build time with no runtime algorithm choice.

use cardano/transaction.{OutputReference, Transaction}
use merkle/simple
use merkle/simple.{Step}

/// Which hash the committed tree uses — applied as a build-time parameter.
pub type Algo {
  Blake2b
  Sha256
}

pub type Datum {
  root: ByteArray,
}

pub type Redeemer {
  /// Raw leaf contents; `simple.includes` domain-separates it internally.
  leaf_data: ByteArray,
  path: List<Step>,
}

validator merkle_gate(algo: Algo) {
  spend(
    datum: Option<Datum>,
    redeemer: Redeemer,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    expect Some(Datum { root }) = datum
    let hash =
      when algo is {
        Blake2b -> simple.blake2b
        Sha256 -> simple.sha256
      }
    simple.includes(hash, root, redeemer.leaf_data, redeemer.path)
  }

  else(_) {
    fail
  }
}
