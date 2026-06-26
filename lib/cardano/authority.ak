//// Governance authority check (the standard "withdraw-zero" pattern).
////
//// A credential authorises a transaction either by signing it (verification
//// key) or by being invoked as a withdrawal script (script credential). The
//// latter lets arbitrary multisig / DAO / time-lock logic gate an action: a
//// zero-lovelace withdrawal forces the ledger to run that script.

use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Credential, Script, VerificationKey}
use cardano/transaction.{Transaction}

/// True iff the transaction is authorised by `authority`:
/// - `VerificationKey(vkh)` — `vkh` is in `extra_signatories`;
/// - `Script(sh)` — `sh` appears as a withdrawal key.
pub fn check_authority(authority: Credential, self: Transaction) -> Bool {
  when authority is {
    VerificationKey(vkh) -> list.has(self.extra_signatories, vkh)
    Script(sh) -> pairs.has_key(self.withdrawals, Script(sh))
  }
}
