// src/chronoforest/digest.rs

use crate::hash::Hash32;
use crate::chronoforest::arena::NodeId;

/// One "peak" (root of a perfect subtree) in the forest.
/// Represents the root of a complete binary tree of a specific height.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Peak {
    /// Arena node ID for this peak
    pub id: NodeId,
    /// Height of this subtree (0 = leaf, 1 = parent of 2 leaves, etc.)
    pub height: u32,
    /// Merkle root hash of this subtree
    pub hash: Hash32,
}

impl Peak {
    pub fn new(id: NodeId, height: u32, hash: Hash32) -> Self {
        Self { id, height, hash }
    }
}

/// Snapshot/digest of the chronological forest state.
/// This is what gets committed to when issuing a VAC.
/// 
/// The digest contains:
/// - All peak hashes (roots of the mountain range)
/// - Total number of leaves
/// 
/// This is sufficient to verify membership/non-membership of any leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest {
    /// Hashes of all peaks, in increasing height order (left to right)
    pub roots: Vec<Hash32>,
    /// Total number of leaves in the forest
    pub size: u32,
}

impl Digest {
    /// Create a new digest from peak hashes and size
    pub fn new(roots: Vec<Hash32>, size: u32) -> Self {
        Self { roots, size }
    }
    
    /// Create an empty digest (no leaves)
    pub fn empty() -> Self {
        Self {
            roots: Vec::new(),
            size: 0,
        }
    }
    
    /// Number of peaks in this digest
    pub fn num_peaks(&self) -> usize {
        self.roots.len()
    }
    
    /// Get a specific peak hash by index
    pub fn peak(&self, index: usize) -> Option<&Hash32> {
        self.roots.get(index)
    }
    
    /// Compute a single commitment hash of the entire digest
    /// This is useful for signing in MAVACS (sign the digest hash)
    pub fn commitment_hash<H: crate::hash::Hasher>(&self) -> Hash32 {
        // Hash all roots together with the size
        let mut parts: Vec<&[u8]> = vec![b"msq:digest"];
        for root in &self.roots {
            parts.push(root.as_ref());
        }
        let size_bytes = self.size.to_le_bytes();
        parts.push(&size_bytes);
        
        H::hash(&parts)
    }
    
    /// Check if this digest represents an empty forest
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
    
    /// Convert to bytes for serialization (for VAC storage)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Write size (4 bytes)
        bytes.extend_from_slice(&self.size.to_le_bytes());
        
        // Write number of roots (4 bytes)
        bytes.extend_from_slice(&(self.roots.len() as u32).to_le_bytes());
        
        // Write each root (32 bytes each)
        for root in &self.roots {
            bytes.extend_from_slice(root.as_ref());
        }
        
        bytes
    }
    
    /// Parse digest from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 {
            return Err("digest too short");
        }
        
        // Read size
        let size = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        
        // Read number of roots
        let num_roots = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        
        // Check length
        let expected_len = 8 + num_roots * 32;
        if bytes.len() != expected_len {
            return Err("invalid digest length");
        }
        
        // Read roots
        let mut roots = Vec::with_capacity(num_roots);
        for i in 0..num_roots {
            let start = 8 + i * 32;
            let end = start + 32;
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&bytes[start..end]);
            roots.push(Hash32(hash_bytes));
        }
        
        Ok(Self { roots, size })
    }
}

// Implement Display for human-readable output
impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest(size={}, peaks={})", self.size, self.roots.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256Hasher;
    
    #[test]
    fn empty_digest() {
        let d = Digest::empty();
        assert_eq!(d.size, 0);
        assert_eq!(d.num_peaks(), 0);
        assert!(d.is_empty());
    }
    
    #[test]
    fn digest_serialization() {
        let roots = vec![
            Hash32([1u8; 32]),
            Hash32([2u8; 32]),
        ];
        let digest = Digest::new(roots.clone(), 42);
        
        let bytes = digest.to_bytes();
        let recovered = Digest::from_bytes(&bytes).unwrap();
        
        assert_eq!(recovered.size, 42);
        assert_eq!(recovered.roots, roots);
    }
    
    #[test]
    fn commitment_hash_deterministic() {
        let roots = vec![Hash32([1u8; 32])];
        let d1 = Digest::new(roots.clone(), 1);
        let d2 = Digest::new(roots, 1);
        
        let h1 = d1.commitment_hash::<Sha256Hasher>();
        let h2 = d2.commitment_hash::<Sha256Hasher>();
        
        assert_eq!(h1, h2);
    }
    
    #[test]
    fn different_digests_different_hashes() {
        let d1 = Digest::new(vec![Hash32([1u8; 32])], 1);
        let d2 = Digest::new(vec![Hash32([2u8; 32])], 1);
        
        let h1 = d1.commitment_hash::<Sha256Hasher>();
        let h2 = d2.commitment_hash::<Sha256Hasher>();
        
        assert_ne!(h1, h2);
    }
}