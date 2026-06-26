//// Test utilities for contracts built on oakshield.
////
//// Helpers to construct `Transaction`/`Input`/`Output` values and MPF proofs
//// in `.test.ak` files. Not imported by any validator, so it is dead-code-
//// eliminated from `plutus.json`.

use aiken/builtin
use aiken/merkle_patricia_forestry.{Leaf}
use aiken/primitive/bytearray
use cardano/address.{Address, Script}
use cardano/assets
use cardano/nullifier
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction}
use cardano/transaction

/// An output at `script_hash`'s address carrying one `(policy, name)` NFT and an
/// inline `datum`.
pub fn script_output(
  script_hash: ByteArray,
  policy: ByteArray,
  name: ByteArray,
  datum: Data,
) -> Output {
  Output {
    address: Address {
      payment_credential: Script(script_hash),
      stake_credential: None,
    },
    value: assets.from_asset(policy, name, 1),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

/// An input spending [script_output](#script_output) at `ref`.
pub fn script_input(
  script_hash: ByteArray,
  policy: ByteArray,
  name: ByteArray,
  datum: Data,
  ref: OutputReference,
) -> Input {
  Input { output_reference: ref, output: script_output(script_hash, policy, name, datum) }
}

/// A transaction with the given inputs / reference inputs / outputs (all other
/// fields are the stdlib placeholder).
pub fn tx(
  inputs: List<Input>,
  reference_inputs: List<Input>,
  outputs: List<Output>,
) -> Transaction {
  Transaction { ..transaction.placeholder, inputs, reference_inputs, outputs }
}

/// An MPF single-neighbour insertion proof: inserts `my_key` into a trie whose
/// only element is `neighbour_key` (value = the [cardano/nullifier](./cardano/nullifier.html)
/// marker, empty bytes). Lets tests exercise nullifier flows without off-chain
/// proof tooling; the on-chain `insert` self-verifies it.
pub fn mpf_insert_proof(
  neighbour_key: ByteArray,
  my_key: ByteArray,
) -> nullifier.Proof {
  let np = builtin.blake2b_256(neighbour_key)
  let mp = builtin.blake2b_256(my_key)
  [Leaf { skip: common_nibbles(np, mp, 0), key: np, value: builtin.blake2b_256(#"") }]
}

fn common_nibbles(a: ByteArray, b: ByteArray, i: Int) -> Int {
  if nibble(a, i) == nibble(b, i) {
    common_nibbles(a, b, i + 1)
  } else {
    i
  }
}

fn nibble(x: ByteArray, i: Int) -> Int {
  if i % 2 == 0 {
    bytearray.at(x, i / 2) / 16
  } else {
    bytearray.at(x, i / 2) % 16
  }
}
