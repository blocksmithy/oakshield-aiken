use cardano/address.{Script, VerificationKey}
use cardano/transaction.{OutputReference, Transaction}
use cardano/transaction
use authority_gate
use authority_gate.{Datum}

const vkh: ByteArray = #"00000000000000000000000000000000000000000000000000000001"

const sh: ByteArray = #"00000000000000000000000000000000000000000000000000000002"

const utxo: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

// Authorised by a signature: owner's key hash is in extra_signatories.
test authority_gate_accepts_signature() {
  let tx = Transaction { ..transaction.placeholder, extra_signatories: [vkh] }
  authority_gate.authority_gate.spend(
    Some(Datum { owner: VerificationKey(vkh) }),
    0,
    utxo,
    tx,
  )
}

// Authorised by the withdraw-zero pattern: owner script appears in withdrawals.
test authority_gate_accepts_withdrawal() {
  let tx =
    Transaction { ..transaction.placeholder, withdrawals: [Pair(Script(sh), 0)] }
  authority_gate.authority_gate.spend(
    Some(Datum { owner: Script(sh) }),
    0,
    utxo,
    tx,
  )
}

// Not authorised: owner's key not present.
test authority_gate_rejects_unauthorised() {
  !authority_gate.authority_gate.spend(
    Some(Datum { owner: VerificationKey(vkh) }),
    0,
    utxo,
    transaction.placeholder,
  )
}
