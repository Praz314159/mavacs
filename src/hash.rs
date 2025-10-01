use sha2::{Digest as _, Sha256};

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Hash32(pub [u8; 32]);

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

pub trait Hasher: Copy + Clone + 'static {
    fn hash(parts: &[&[u8]]) -> Hash32;
}

#[derive(Copy, Clone)]
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash(parts: &[&[u8]]) -> Hash32 {
        let mut h = Sha256::new();
        for p in parts { h.update(p); }
        let out = h.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(&out);
        Hash32(b)
    }
}
