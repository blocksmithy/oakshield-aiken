//// Example: gate a spend behind a governance credential.
////
//// The datum names an authorising credential; the spend succeeds only if the
//// transaction is authorised by it (a signature, or the withdraw-zero script
//// pattern). Demonstrates [cardano/authority](../lib/cardano/authority.html).

use cardano/address.{Credential}
use cardano/authority
use cardano/transaction.{OutputReference, Transaction}

pub type Datum {
  owner: Credential,
}

validator authority_gate {
  spend(
    datum: Option<Datum>,
    _redeemer: Data,
    _utxo: OutputReference,
    self: Transaction,
  ) {
    expect Some(Datum { owner }) = datum
    authority.check_authority(owner, self)
  }

  else(_) {
    fail
  }
}
