use crate::chronoforest::arena::{Arena, Node, NodeId};
use crate::hash::{Hash32, Hasher, Sha256Hasher};

/// One “peak” (root of a perfect subtree) in the forest.
#[derive(Copy, Clone, Debug)]
pub struct Peak {
    pub id: NodeId,
    pub height: u32,
    pub hash: Hash32,
}

/// Snapshot/digest = current peak hashes + size.
#[derive(Clone, Debug)]
pub struct Digest {
    pub roots: Vec<[u8; 32]>,
    pub size: u32,
}

/// MerkleSquare surface: peaks as `Roots`, plus running `Size` and fixed `depth`.
pub struct MerkleSquare<H: Hasher = Sha256Hasher> {
    /// Peaks in increasing height order (left..right). Treat as “roots”.
    pub roots: Vec<Peak>,
    pub size: u32,
    depth: u32,

    // internals
    arena: Arena,
    hasher: H,
}

impl<H: Hasher> MerkleSquare<H> {
    /// Create an empty MerkleSquare that can hold up to 2^depth leaves.
    pub fn new(depth: u32) -> Self {
        Self {
            roots: Vec::new(),
            size: 0,
            depth,
            arena: Arena::new(),
            hasher: DefaultHasher::<H>::get(),
        }
    }

    /// Append a (key, value, signature) leaf. Order affects the final roots (by design).
    pub fn append(&mut self, key: &[u8], value: &[u8], signature: &[u8]) -> Result<(), &'static str> {
        if self.is_full() { return Err("forest full"); }

        let pos = self.size;
        let content = compute_content_hash::<H>(key, value, signature, pos);
        // For now, prefix = H(key). You can swap this for your real prefix derivation later.
        let prefix = make_prefix_from_key::<H>(key);
        let leaf_hash = compute_leaf_hash::<H>(prefix, content);

        let leaf_id = self.arena.push(Node::Leaf { hash: leaf_hash, pos });
        let mut carry = Peak { id: leaf_id, height: 0, hash: leaf_hash };

        // Bag with same-height peaks (MMR-style binary carry).
        while let Some(last) = self.roots.last().copied() {
            if last.height != carry.height { break; }
            // last is the older (left), carry is the newer (right)
            let parent = self.bag(last, carry);
            self.roots.pop();
            carry = parent;
        }

        self.roots.push(carry);
        self.size += 1;
        Ok(())
    }

    /// Current digest (peak hashes + size).
    pub fn get_digest(&self) -> Digest {
        Digest {
            roots: self.roots.iter().map(|p| p.hash.0).collect(),
            size: self.size,
        }
    }

    /// Is the current forest full (2^depth leaves)?
    #[inline] pub fn is_full(&self) -> bool { self.size == (1u32 << self.depth) }

    /// Internal: compute parent from two same-height peaks (left, right).
    fn bag(&mut self, left: Peak, right: Peak) -> Peak {
        debug_assert_eq!(left.height, right.height);

        let h = H::hash(&[left.hash.as_ref(), right.hash.as_ref()]);
        // TODO(prefix): incorporate prefix-tree parent hash when you wire it:
        //   parent_hash = H(left.hash || right.hash || prefix_parent_hash)

        let parent = Node::Internal {
            left: left.id,
            right: right.id,
            hash: h,
            height: left.height + 1,
            shift: (self.node_shift(left.id) / 2),
        };
        let id = self.arena.push(parent);
        Peak { id, height: left.height + 1, hash: h }
    }

    /// Optional helper: compute node's shift = pos >> height (for future proofs/ranges).
    fn node_shift(&self, id: NodeId) -> u32 {
        match self.arena.get(id) {
            Node::Leaf { pos, .. } => *pos,
            Node::Internal { shift, .. } => *shift,
        }
    }
}

// ------------------------- hashing helpers (skeleton) -------------------------

/// Domain tag helpers (replace/expand if you want stronger separation).
const TAG_PREFIX: &[u8] = b"msq:prefix";
const TAG_CONTENT: &[u8] = b"msq:content";
const TAG_LEAF: &[u8] = b"msq:leaf";

fn make_prefix_from_key<H: Hasher>(key: &[u8]) -> Hash32 {
    H::hash(&[TAG_PREFIX, key])
}

fn compute_content_hash<H: Hasher>(key: &[u8], value: &[u8], signature: &[u8], pos: u32) -> Hash32 {
    let pos_le = pos.to_le_bytes();
    H::hash(&[TAG_CONTENT, key, value, signature, &pos_le])
}

fn compute_leaf_hash<H: Hasher>(prefix: Hash32, content: Hash32) -> Hash32 {
    H::hash(&[TAG_LEAF, prefix.as_ref(), content.as_ref()])
}

// ------------------------------- Default hasher -------------------------------

/// A tiny helper to default to Sha256 without requiring H: Default.
struct DefaultHasher<H: Hasher>(core::marker::PhantomData<H>);
impl<H: Hasher> DefaultHasher<H> {
    fn get() -> H { // H has no state; it's a zero-sized type for our Sha256Hasher
        // SAFETY: all our Hashers are ZSTs (like Sha256Hasher). If you add stateful hashers later,
        // switch to requiring H: Default.
        unsafe { core::mem::MaybeUninit::<H>::zeroed().assume_init() }
    }
}

// ------------------------------- smoke tests ---------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256Hasher;


    #[test]
    fn append_and_digest() {
        let mut msq: MerkleSquare<Sha256Hasher> = MerkleSquare::new(10);
        msq.append(b"a", b"1", b"sig").unwrap();
        msq.append(b"b", b"2", b"sig").unwrap();
        let d = msq.get_digest();
        assert_eq!(d.size, 2);
        assert_eq!(d.roots.len(), 1, "2 leaves -> one peak of height 1");
    }

    #[test]
    fn peaks_binary_carry() {
        let mut msq: MerkleSquare = MerkleSquare::new(10);
        for i in 0..13 {
            msq.append(b"k", &[(i as u8)], b"s").unwrap();
        }
        // 13 = 8 + 4 + 1 -> three peaks
        assert_eq!(msq.roots.len(), 3);
        assert_eq!(msq.size, 13);
        assert!(msq.roots.windows(2).all(|w| w[0].height > w[1].height));
    }
}
