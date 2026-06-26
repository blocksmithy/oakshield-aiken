//! Off-chain codec for the oakshield Cardano wire format.
//!
//! Parses and serializes the `vk.cardano.bin` / `proof.cardano.bin` /
//! `public.cardano.bin` files the prover emits — the byte-exact inverse of the
//! on-chain `wire.ak` decoders. All multi-byte integers are big-endian `u32`;
//! curve points are compressed (G1 = 48 B, G2 = 96 B); scalars are 32 B.
//!
//! The redeemer can ride as the raw proof bytes plus the journal: the on-chain
//! validator parses them with `wire.parse_proof`, so no PlutusData encoding is
//! required off-chain. See [`Redeemer`].

pub const G1: usize = 48;
pub const G2: usize = 96;
pub const SCALAR: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Ran past the end of the buffer.
    Truncated,
    /// Trailing bytes remained after a complete parse.
    TrailingBytes,
}

// ── reader ───────────────────────────────────────────────────────────────────

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn vec(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        Ok(self.take(n)?.to_vec())
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    fn finish(self) -> Result<(), Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

// ── types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub compressed: Vec<u8>,   // 48 B G1
    pub uncompressed: Vec<u8>, // 96 B (x_be ‖ y_be)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
    pub commitments: Vec<Commitment>,
    pub pok: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    pub alpha_g1: Vec<u8>,
    pub beta_g2: Vec<u8>,
    pub gamma_g2: Vec<u8>,
    pub delta_g2: Vec<u8>,
    pub ic: Vec<Vec<u8>>,
    pub pedersen_g: Vec<Vec<u8>>,
    pub pedersen_g_sigma_neg: Vec<Vec<u8>>,
    /// BSB22 committed public-input indices, per commitment. The native
    /// `risc0-groth16-bls` circuit commits no public wire, so on-chain
    /// (`wire.parse_vk`) every inner list must be empty (`[[]]`); this codec
    /// stays general for byte-exact round-tripping.
    pub committed: Vec<Vec<u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputs {
    pub n_inner_pub: u32,
    pub n_limbs_per_scalar: u32,
    /// `n_inner_pub * n_limbs_per_scalar` scalars, each 32 bytes big-endian.
    pub scalars: Vec<Vec<u8>>,
}

// ── Proof ────────────────────────────────────────────────────────────────────

impl Proof {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let a = r.vec(G1)?;
        let b = r.vec(G2)?;
        let c = r.vec(G1)?;
        let n_c = r.u32()? as usize;
        let mut commitments = Vec::with_capacity(n_c);
        for _ in 0..n_c {
            commitments.push(Commitment {
                compressed: r.vec(G1)?,
                uncompressed: r.vec(G2)?,
            });
        }
        let pok = r.vec(G1)?;
        r.finish()?;
        Ok(Proof { a, b, c, commitments, pok })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.a);
        out.extend_from_slice(&self.b);
        out.extend_from_slice(&self.c);
        put_u32(&mut out, self.commitments.len() as u32);
        for c in &self.commitments {
            out.extend_from_slice(&c.compressed);
            out.extend_from_slice(&c.uncompressed);
        }
        out.extend_from_slice(&self.pok);
        out
    }
}

// ── VerificationKey ──────────────────────────────────────────────────────────

impl VerificationKey {
    /// Public-input count, derived as `ic_count - 1 - n_commitments`. Assumes a
    /// well-formed VK as produced by [`parse`](Self::parse); a hand-built struct
    /// with too few `ic` entries underflow-panics.
    pub fn public_input_count(&self) -> usize {
        self.ic.len() - 1 - self.pedersen_g.len()
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let alpha_g1 = r.vec(G1)?;
        let beta_g2 = r.vec(G2)?;
        let gamma_g2 = r.vec(G2)?;
        let delta_g2 = r.vec(G2)?;
        let ic_count = r.u32()? as usize;
        let mut ic = Vec::with_capacity(ic_count);
        for _ in 0..ic_count {
            ic.push(r.vec(G1)?);
        }
        let n_c = r.u32()? as usize;
        let mut pedersen_g = Vec::with_capacity(n_c);
        let mut pedersen_g_sigma_neg = Vec::with_capacity(n_c);
        for _ in 0..n_c {
            pedersen_g.push(r.vec(G2)?);
            pedersen_g_sigma_neg.push(r.vec(G2)?);
        }
        let mut committed = Vec::with_capacity(n_c);
        for _ in 0..n_c {
            let count = r.u32()? as usize;
            let mut indices = Vec::with_capacity(count);
            for _ in 0..count {
                indices.push(r.u32()?);
            }
            committed.push(indices);
        }
        r.finish()?;
        Ok(VerificationKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
            pedersen_g,
            pedersen_g_sigma_neg,
            committed,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.alpha_g1);
        out.extend_from_slice(&self.beta_g2);
        out.extend_from_slice(&self.gamma_g2);
        out.extend_from_slice(&self.delta_g2);
        put_u32(&mut out, self.ic.len() as u32);
        for k in &self.ic {
            out.extend_from_slice(k);
        }
        put_u32(&mut out, self.pedersen_g.len() as u32);
        for (g, sigma) in self.pedersen_g.iter().zip(&self.pedersen_g_sigma_neg) {
            out.extend_from_slice(g);
            out.extend_from_slice(sigma);
        }
        for indices in &self.committed {
            put_u32(&mut out, indices.len() as u32);
            for &i in indices {
                put_u32(&mut out, i);
            }
        }
        out
    }
}

// ── PublicInputs ─────────────────────────────────────────────────────────────

impl PublicInputs {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let n_inner_pub = r.u32()?;
        let n_limbs_per_scalar = r.u32()?;
        let count = (n_inner_pub as usize) * (n_limbs_per_scalar as usize);
        let mut scalars = Vec::with_capacity(count);
        for _ in 0..count {
            scalars.push(r.vec(SCALAR)?);
        }
        r.finish()?;
        Ok(PublicInputs { n_inner_pub, n_limbs_per_scalar, scalars })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, self.n_inner_pub);
        put_u32(&mut out, self.n_limbs_per_scalar);
        for s in &self.scalars {
            out.extend_from_slice(s);
        }
        out
    }
}

// ── redeemer ─────────────────────────────────────────────────────────────────

/// The data a `tx_inclusion`-style spend needs: the raw proof wire bytes and
/// the committed journal. The on-chain validator parses `proof_wire` with
/// `wire.parse_proof` and derives the public inputs from `journal`; the two
/// fields stay as opaque byte strings, so no inner PlutusData encoding is
/// required.
///
/// The caller serialises this as PlutusData `Constr(0, [Bytes proof_wire,
/// Bytes journal])` for the redeemer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redeemer {
    pub proof_wire: Vec<u8>,
    pub journal: Vec<u8>,
}
