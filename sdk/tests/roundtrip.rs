//! Round-trip the production ceremony fixtures through the codec: parse, then
//! re-serialize, and assert the bytes are identical.

use oakshield_sdk::{Proof, PublicInputs, VerificationKey};

const VK: &[u8] = include_bytes!("fixtures/vk.cardano.bin");
const PROOF: &[u8] = include_bytes!("fixtures/proof.cardano.bin");
const PUBLIC: &[u8] = include_bytes!("fixtures/public.cardano.bin");

#[test]
fn vk_roundtrips() {
    let vk = VerificationKey::parse(VK).expect("parse vk");
    assert_eq!(vk.ic.len(), 7);
    assert_eq!(vk.pedersen_g.len(), 1);
    assert_eq!(vk.public_input_count(), 5);
    assert_eq!(vk.committed, vec![Vec::<u32>::new()]); // [[]]
    assert_eq!(vk.to_bytes(), VK);
}

#[test]
fn proof_roundtrips() {
    let p = Proof::parse(PROOF).expect("parse proof");
    assert_eq!(p.commitments.len(), 1);
    assert_eq!(p.a.len(), 48);
    assert_eq!(p.b.len(), 96);
    assert_eq!(p.commitments[0].uncompressed.len(), 96);
    assert_eq!(p.to_bytes(), PROOF);
}

#[test]
fn public_roundtrips() {
    let pi = PublicInputs::parse(PUBLIC).expect("parse public");
    assert_eq!(pi.n_inner_pub, 5);
    assert_eq!(pi.n_limbs_per_scalar, 1); // native
    assert_eq!(pi.scalars.len(), 5);
    // public[4] is the control_id (BLS_IDENTITY_CONTROL_ID, big-endian).
    assert_eq!(
        pi.scalars[4],
        hex(b"68934068200916e1b61cfddab9b6622c587fd06034056705447a7c4d3ee7535b")
    );
    assert_eq!(pi.to_bytes(), PUBLIC);
}

#[test]
fn rejects_truncated() {
    assert!(Proof::parse(&PROOF[..PROOF.len() - 1]).is_err());
    assert!(VerificationKey::parse(&VK[..10]).is_err());
}

fn hex(s: &[u8]) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| {
            let h = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("bad hex"),
            };
            (h(s[2 * i]) << 4) | h(s[2 * i + 1])
        })
        .collect()
}
