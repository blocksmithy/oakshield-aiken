//// Identity-NFT registry lookups.
////
//// A common Cardano pattern: a unique UTxO is marked by a single NFT (policy
//// + asset name) held at a script address, so other transactions can locate
//// it deterministically as a reference input. These helpers find such a UTxO
//// and fail when the uniqueness assumption is violated.

use aiken/collection/list
use cardano/address.{Script}
use cardano/assets.{AssetName, PolicyId, quantity_of}
use cardano/transaction.{Input, Transaction}

// Pick the single input from `items` held at `policy_id`'s script address that
// carries exactly one of the `(policy_id, asset_name)` NFT. Fails if zero or
// more than one match — the fail is the uniqueness guarantee.
fn unique_with_nft(
  items: List<Input>,
  policy_id: PolicyId,
  asset_name: AssetName,
) -> Input {
  expect [the_one] =
    list.filter(
      items,
      fn(i) {
        and {
          i.output.address.payment_credential == Script(policy_id),
          quantity_of(i.output.value, policy_id, asset_name) == 1,
        }
      },
    )
  the_one
}

/// Find the unique reference input held at `policy_id`'s script address that
/// carries exactly one of the `(policy_id, asset_name)` NFT. Fails if zero or
/// more than one match — the fail is the uniqueness guarantee.
pub fn reference_input_with_nft(
  self: Transaction,
  policy_id: PolicyId,
  asset_name: AssetName,
) -> Input {
  unique_with_nft(self.reference_inputs, policy_id, asset_name)
}

/// Find the unique spent input held at `policy_id`'s script address that
/// carries exactly one of the `(policy_id, asset_name)` NFT. Fails if zero or
/// more than one match.
pub fn input_with_nft(
  self: Transaction,
  policy_id: PolicyId,
  asset_name: AssetName,
) -> Input {
  unique_with_nft(self.inputs, policy_id, asset_name)
}
