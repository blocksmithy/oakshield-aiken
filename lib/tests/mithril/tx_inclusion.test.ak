use cardano/nullifier
use dev/ceremony
use dev/testkit
use mithril/journal
use mithril/tx_inclusion.{Consume}
use mithril/tx_inclusion

// Synthetic oaks_tx journal: v1, component_mode 0, two transactions, root = 0x34..34.
const tx_journal: ByteArray =
  #"343434343434343434343434343434343434343434343434343434343434343409090909090909090909090909090909090909090909090909090909090909092525252525252525252525252525252525252525252525252525252525252525dfbacd00000000000100000000000000020000001d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b000000000000000000000000000000009dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f50300000000000000000000000000000000"

const root: ByteArray =
  #"3434343434343434343434343434343434343434343434343434343434343434"

const present_tx: ByteArray =
  #"1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b"

// Root binding is enforced before the (expensive) pairing: a mismatched
// certified root aborts regardless of the proof.
test rejects_root_mismatch() fail {
  tx_inclusion.verify_inclusion(
    ceremony.proof(),
    tx_journal,
    ceremony.verification_key(),
    ceremony.risc0_params(),
    #"0000000000000000000000000000000000000000000000000000000000000000",
    present_tx,
  )
}

// A tx_id absent from the committed records aborts before the pairing.
test rejects_absent_tx() fail {
  tx_inclusion.verify_inclusion(
    ceremony.proof(),
    tx_journal,
    ceremony.verification_key(),
    ceremony.risc0_params(),
    root,
    #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  )
}

// verify_and_consume binds the journal's root before anything else: a mismatched
// certified root aborts (before the pairing and before any nullify). The full
// accept path needs a real oaks_tx proof fixture (exercised by the
// tx_inclusion_nullifier validator end to end).
test verify_and_consume_rejects_root_mismatch() fail {
  tx_inclusion.verify_and_consume(
    ceremony.proof(),
    tx_journal,
    ceremony.verification_key(),
    ceremony.risc0_params(),
    #"0000000000000000000000000000000000000000000000000000000000000000",
    nullifier.empty_root,
    [Consume { tx_id: present_tx, proof: [] }],
  ) != #""
}

// ── consume / nullifier behaviour ────────────────────────────────────────────
//
// The nullifier set keys on `tx_id`. A proof carrying two tx_ids can be
// consumed in one transaction or split across two, and each tx_id can be
// nullified at most once.
//
// MPF insertion proofs are generated in-test from the `blake2b_256` builtin:
// for a single-neighbour trie the proof is one `Leaf` step. The on-chain
// `insert` self-verifies these (it aborts unless `excluding(key, proof)` equals
// the current root), so a wrong proof fails the test.

const tx1: ByteArray =
  #"1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b"

const tx2: ByteArray =
  #"9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f503"

const absent_tx: ByteArray =
  #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// v2 journal (proof_version 2, mode 2 → 80-byte records) carrying tx1, tx2.
const tx_journal_v2: ByteArray =
  #"343434343434343434343434343434343434343434343434343434343434343409090909090909090909090909090909090909090909090909090909090909092525252525252525252525252525252525252525252525252525252525252525dfbacd00000000000200000002000000020000001d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b0a000000000000001400000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f5030b000000000000001500000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// Single-neighbour MPF insertion proof — from the testkit.
fn leaf_proof(neighbor_key: ByteArray, my_key: ByteArray) -> nullifier.Proof {
  testkit.mpf_insert_proof(neighbor_key, my_key)
}

fn decode(j: ByteArray) {
  journal.decode_tx_inclusion(j)
}

// Both tx_ids consumed in ONE transaction (empty set → {tx1, tx2}).
fn both_in_one(j: ByteArray) -> ByteArray {
  let set =
    tx_inclusion.consume_inclusions_unchecked(
      j,
      decode(j),
      #"0000000000000000000000000000000000000000000000000000000000000000",
      [
        Consume { tx_id: tx1, proof: [] },
        Consume { tx_id: tx2, proof: leaf_proof(tx1, tx2) },
      ],
    )
  set
}

test consume_both_in_one_transaction_v1() {
  // Anchor to the concrete spend-path state (both tx_ids inserted), not merely
  // "non-empty": consume must reach exactly the directly-computed root.
  both_in_one(tx_journal) == nullifier.spend(
    nullifier.spend(#"0000000000000000000000000000000000000000000000000000000000000000", tx1, []),
    tx2,
    leaf_proof(tx1, tx2),
  )
}

// The SAME proof split across two transactions reaches the same set state.
test consume_split_across_two_transactions_v1() {
  let j = tx_journal
  let after_a =
    tx_inclusion.consume_inclusions_unchecked(
      j,
      decode(j),
      #"0000000000000000000000000000000000000000000000000000000000000000",
      [Consume { tx_id: tx1, proof: [] }],
    )
  let after_b =
    tx_inclusion.consume_inclusions_unchecked(
      j,
      decode(j),
      after_a,
      [Consume { tx_id: tx2, proof: leaf_proof(tx1, tx2) }],
    )
  after_b == both_in_one(j)
}

// Same behaviour for a v2 (mode 2, 80-byte record) journal.
test consume_both_in_one_transaction_v2() {
  both_in_one(tx_journal_v2) == both_in_one(tx_journal)
}

// Order independence: inserting tx1-then-tx2 yields the SAME root as
// tx2-then-tx1. An MPF is canonical — the root is a function of the key set,
// not the insertion order — so no ordering needs to be enforced.
test nullifier_order_independent() {
  let a =
    nullifier.spend(
      nullifier.spend(#"0000000000000000000000000000000000000000000000000000000000000000", tx1, []),
      tx2,
      leaf_proof(tx1, tx2),
    )
  let b =
    nullifier.spend(
      nullifier.spend(#"0000000000000000000000000000000000000000000000000000000000000000", tx2, []),
      tx1,
      leaf_proof(tx2, tx1),
    )
  a == b
}

// Replay: nullifying tx1 again after it is already spent aborts.
test consume_replay_rejected() fail {
  let j = tx_journal
  let after_a =
    tx_inclusion.consume_inclusions_unchecked(
      j,
      decode(j),
      #"0000000000000000000000000000000000000000000000000000000000000000",
      [Consume { tx_id: tx1, proof: [] }],
    )
  tx_inclusion.consume_inclusions_unchecked(
    j,
    decode(j),
    after_a,
    [Consume { tx_id: tx1, proof: leaf_proof(tx2, tx1) }],
  ) != #""
}

// A tx_id not committed in the journal cannot be nullified.
test consume_uncommitted_rejected() fail {
  let j = tx_journal
  tx_inclusion.consume_inclusions_unchecked(
    j,
    decode(j),
    #"0000000000000000000000000000000000000000000000000000000000000000",
    [Consume { tx_id: absent_tx, proof: [] }],
  ) != #""
}

// Consuming the same tx_id twice within ONE transaction also aborts (the second
// insert sees it already present).
test consume_duplicate_in_one_tx_rejected() fail {
  let j = tx_journal
  tx_inclusion.consume_inclusions_unchecked(
    j,
    decode(j),
    #"0000000000000000000000000000000000000000000000000000000000000000",
    [
      Consume { tx_id: tx1, proof: [] },
      Consume { tx_id: tx1, proof: leaf_proof(tx2, tx1) },
    ],
  ) != #""
}
