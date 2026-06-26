//// State-thread helpers.
////
//// A stateful contract keeps its state in a UTxO marked by a unique NFT (the
//// "state thread"). On each spend it must produce a continuing output at the
//// same address carrying that NFT and the new datum. These helpers locate that
//// output and read its datum, aborting if it is missing or ambiguous, so the
//// state cannot be dropped, forked, or replaced.

use aiken/collection/list
use cardano/address.{Address}
use cardano/assets.{AssetName, PolicyId, quantity_of}
use cardano/transaction.{InlineDatum, Output, OutputReference, Transaction,
  find_input}

/// The unique output at `address` carrying exactly one `(policy, name)` NFT.
/// Fails if there is no such output, or more than one.
pub fn continuing_output(
  self: Transaction,
  address: Address,
  policy: PolicyId,
  name: AssetName,
) -> Output {
  expect [the_one] =
    list.filter(
      self.outputs,
      fn(o) { o.address == address && quantity_of(o.value, policy, name) == 1 },
    )
  the_one
}

/// The continuing state-thread output, resolving the spending input's own
/// address from `own_ref` (the `OutputReference` passed to a spend handler).
pub fn continuing_output_of(
  self: Transaction,
  own_ref: OutputReference,
  policy: PolicyId,
  name: AssetName,
) -> Output {
  expect Some(own) = find_input(self.inputs, own_ref)
  continuing_output(self, own.output.address, policy, name)
}

/// The inline datum of the continuing state-thread output, as `Data`. Cast it
/// at the call site, e.g. `expect MyDatum { .. } = continuing_datum(...)`.
pub fn continuing_datum(
  self: Transaction,
  own_ref: OutputReference,
  policy: PolicyId,
  name: AssetName,
) -> Data {
  expect InlineDatum(d) = continuing_output_of(self, own_ref, policy, name).datum
  d
}
