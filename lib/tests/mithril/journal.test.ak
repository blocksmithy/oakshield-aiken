use aiken/primitive/bytearray
use mithril/journal

// A real 148-byte oaks_comp chain-proof journal (Mainnet).
const chain_journal: ByteArray =
  #"25acfcfe76db231ca9fb394937e9ebde07ba3608cffd51e3a164413bb83bf64109cbd6cf68fb163f524f5e0ef0f457d7c5a737471d2e696b473cc3f84b0494ac610000000000000050fca3d8ac3768a385ed9b56d48a2fa194496d5a25e8331151a8279ecf7a791b28000000342eb1f9e977b91a87fbb24ce4ac96253182ad5b50ad979bfe5a6bc5a0cd123edfbacd0000000000"

test decode_chain_proof_real() {
  let tip = journal.decode_chain_proof(chain_journal)
  and {
    tip.genesis_hash == #"25acfcfe76db231ca9fb394937e9ebde07ba3608cffd51e3a164413bb83bf641",
    tip.tip_hash == #"09cbd6cf68fb163f524f5e0ef0f457d7c5a737471d2e696b473cc3f84b0494ac",
    tip.tx_merkle_root == #"342eb1f9e977b91a87fbb24ce4ac96253182ad5b50ad979bfe5a6bc5a0cd123e",
    tip.block_number == 13482719,
  }
}

test decode_chain_proof_rejects_short() fail {
  let tip = journal.decode_chain_proof(#"00")
  tip.block_number == 0
}

// Synthetic oaks_tx journal: v1, component_mode 0, two transactions.
const tx_journal: ByteArray =
  #"343434343434343434343434343434343434343434343434343434343434343409090909090909090909090909090909090909090909090909090909090909092525252525252525252525252525252525252525252525252525252525252525dfbacd00000000000100000000000000020000001d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b000000000000000000000000000000009dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f50300000000000000000000000000000000"

test decode_tx_inclusion_header() {
  let d = journal.decode_tx_inclusion(tx_journal)
  and {
    d.tx_merkle_root == #"3434343434343434343434343434343434343434343434343434343434343434",
    d.tip_hash == #"0909090909090909090909090909090909090909090909090909090909090909",
    d.cert_block_number == 13482719,
    d.proof_version == 1,
    d.mode == 0,
    d.tx_count == 2,
  }
}

test tx_committed_present() {
  let d = journal.decode_tx_inclusion(tx_journal)
  and {
    journal.tx_committed(
      tx_journal,
      d,
      #"1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b",
    ),
    journal.tx_committed(
      tx_journal,
      d,
      #"9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f503",
    ),
  }
}

test tx_committed_absent() {
  let d = journal.decode_tx_inclusion(tx_journal)
  !journal.tx_committed(
    tx_journal,
    d,
    #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  )
}

// A journal whose declared tx_count disagrees with its byte length is rejected.
test decode_tx_inclusion_rejects_truncated() fail {
  let d = journal.decode_tx_inclusion(bytearray.take(tx_journal, 150))
  d.tx_count == 2
}

// Mode 2 (Components): 80-byte records (tx_id, block, slot, typed_tree_root).
const tx_journal_mode2: ByteArray =
  #"343434343434343434343434343434343434343434343434343434343434343409090909090909090909090909090909090909090909090909090909090909092525252525252525252525252525252525252525252525252525252525252525dfbacd00000000000200000002000000020000001d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b0a000000000000001400000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f5030b000000000000001500000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

test decode_tx_inclusion_mode2() {
  let d = journal.decode_tx_inclusion(tx_journal_mode2)
  and {
    d.mode == 2,
    d.proof_version == 2,
    d.tx_count == 2,
  }
}

test tx_committed_mode2_present() {
  let d = journal.decode_tx_inclusion(tx_journal_mode2)
  journal.tx_committed(
    tx_journal_mode2,
    d,
    #"9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f503",
  )
}

// A mode-2 tx_id absent from the 80-byte records is not matched (stride 80).
test tx_committed_mode2_absent() {
  let d = journal.decode_tx_inclusion(tx_journal_mode2)
  !journal.tx_committed(
    tx_journal_mode2,
    d,
    #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  )
}

// Unknown proof_version (3) is rejected.
test decode_rejects_bad_version() fail {
  let d =
    journal.decode_tx_inclusion(
      #"343434343434343434343434343434343434343434343434343434343434343409090909090909090909090909090909090909090909090909090909090909092525252525252525252525252525252525252525252525252525252525252525dfbacd0000000000030000000000000000000000",
    )
  d.tx_count == 0
}

// Unknown mode (7) is rejected.
test decode_rejects_bad_mode() fail {
  let d =
    journal.decode_tx_inclusion(
      #"343434343434343434343434343434343434343434343434343434343434343409090909090909090909090909090909090909090909090909090909090909092525252525252525252525252525252525252525252525252525252525252525dfbacd0000000000010000000700000000000000",
    )
  d.tx_count == 0
}

// False-positive resistance: a 32-byte value present in the journal but NOT at
// a record boundary (here, the tx_merkle_root in the header) is not matched.
test tx_committed_no_header_false_positive() {
  let d = journal.decode_tx_inclusion(tx_journal)
  !journal.tx_committed(
    tx_journal,
    d,
    #"3434343434343434343434343434343434343434343434343434343434343434",
  )
}
