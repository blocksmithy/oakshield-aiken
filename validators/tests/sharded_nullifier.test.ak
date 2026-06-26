use cardano/nullifier
use cardano/transaction.{OutputReference}
use dev/testkit
use sharded_nullifier
use sharded_nullifier.{Datum, Redeemer}

const script: ByteArray = #"00000000000000000000000000000000000000000000000000000003"

const set_policy: ByteArray = #"00000000000000000000000000000000000000000000000000000009"

const set_name: ByteArray = #"73686172640a"

// 0x1d = 29; 29 % 16 = 13 → home shard 13.
const k1: ByteArray =
  #"1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b"

const ref: OutputReference =
  OutputReference { transaction_id: #"", output_index: 0 }

// Spend in the correct shard (13 of 16): insert k1 into the empty set and
// continue with the updated root.
test sharded_nullifier_accepts_in_shard() {
  let old_root = #"0000000000000000000000000000000000000000000000000000000000000000"
  let new_root = nullifier.spend(#"0000000000000000000000000000000000000000000000000000000000000000", k1, [])
  let datum = Datum { root: old_root }
  let tx =
    testkit.tx(
      [testkit.script_input(script, set_policy, set_name, datum, ref)],
      [],
      [testkit.script_output(script, set_policy, set_name, Datum { root: new_root })],
    )
  sharded_nullifier.sharded_nullifier.spend(
    16,
    13,
    set_policy,
    set_name,
    Some(datum),
    Redeemer { nullifier: k1, proof: [] },
    ref,
    tx,
  )
}

// k1 belongs to shard 13, so a validator for shard 0 must reject it.
test sharded_nullifier_rejects_wrong_shard() fail {
  let old_root = #"0000000000000000000000000000000000000000000000000000000000000000"
  let new_root = nullifier.spend(#"0000000000000000000000000000000000000000000000000000000000000000", k1, [])
  let datum = Datum { root: old_root }
  let tx =
    testkit.tx(
      [testkit.script_input(script, set_policy, set_name, datum, ref)],
      [],
      [testkit.script_output(script, set_policy, set_name, Datum { root: new_root })],
    )
  sharded_nullifier.sharded_nullifier.spend(
    16,
    0,
    set_policy,
    set_name,
    Some(datum),
    Redeemer { nullifier: k1, proof: [] },
    ref,
    tx,
  )
}
