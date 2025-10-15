/// This is an implementation of a Merkle Tree. Merkle trees are essential 
/// to a fully hash-based implementation of AVACS. We can use them both as 
/// dynamic universal accumulators for the Issuer's CMS as well as a static 
/// vector commitments for the VAC.  
///
/// The Merkle Tree is the fundamental building block required for more complex 
/// authenticated data structures. 
///     -- Patricia Tries with non-membership proofs 
///     -- Merkle Mountain Ranges for dynamism in the passive revocation regime 
/// 
/// It's important for the implementation to be very robust (should make heavy and 
/// intelligent use of traits) and also fast/memory efficient. 
///  

use crate::crypto::abstract_primitives::vector_commitment::VectorCommitment;
use crate::crypto::merkle::errors::TreeIndexError;
use sha3::{Digest, Sha3_256};

/// This is typically called a padding rule. Now, one thing that is interesting 
/// to consider here is the difference between a merkle patricia trie and a merkle 
/// tree. Merkle trees typically are full trees of arity two. But in general, trees 
/// can have any arity. Tries on the other hand don't necessarily have to be full. 
/// Padding makes sense of course when the tree must be full. 
pub enum PaddingScheme {
    Zero,
    Copy(Vec<u8>), // the associated vector will contain the precomputed indices of each level.
    Random(u8),
}

pub enum TreeStorageType {
    StoredLeaves(Vec<Vec<u8>>),
    StoredLeavesAndCalculatedHashes(Vec<Vec<u8>>),
}

/// TODO: A merkle tree should be generic over a hash function. This 
/// is an object that implements the hasher trait. 
/// 
/// TODO: We also want a separate type for authentication path. The generate  
///
/// TODO: One thing that needs to change here is the framing of "attribute vector
/// commitment". We need merkle trees in a lot of different places. When designing 
/// the type system, we want a base merkle tree construction that can be used in a lot 
/// of different places, since it will have to be. If we had a trait "hashable", we could 
/// have an associated type leaf that must be hashable. Because we will have an attribute type 
/// that is also hashable, the attribute can serve as a leaf in a merkle tree. Then, we 
/// can use a merkle tree as a vector commitment over attributes directly when creating 
/// credentials. 
///
/// TODO: The interface should probably be improved. Function names here are pretty horrendous and 
/// can be cleaned. I think also there's a question about what functions should be helper
/// functions. 
///
/// TODO: It's worth looking more closely at the following paper:
/// https://eprint.iacr.org/2023/1830.pdf. There are two reasons for this: 
///     1. I know this is the exposition in most places, and that I glossed over the point so that
///        we could move forward, but it isn't always the case that internal nodes are simply
///        computed as H(left_child||right_child). In general, we define some sort of "addition"
///        rule, which happens classically to be concatenation. 
///     2. Homomorphic trees provide sublinear updates. These are the lowerbounds that are used in
///        my thesis. 
///
/// In general, I think we need to come up with a trait system for merkle objects: tries, trees, 
/// homomorphic trees, leaves, paths, etc. It makes sense that a tree completes a trie and that a 
/// homomorphic tree is an extension of a tree. 
///
pub struct MerkleAVC {
    pub root: Vec<u8>,
    pub height: u16,
    pub num_attributes: u16,
    pub padding_scheme: PaddingScheme,
    //hash: Hasher,
    pub stored_values: TreeStorageType,
}

impl MerkleAVC {
    const fn root_index(height: u16) -> u16 {
        2_u16.pow(height as u32) - 2
    }

    const fn last_leaf_index(height: u16) -> u16 {
        2_u16.pow(height as u32 - 1) - 1
    }

    const fn root_index_copy_padding(num_attributes: u16) -> u16 {
        // The worst case for zero padding is when a = 2^k + 1. The tree will have 2^(k+2) - 1 nodes.
            //For copy padding, the tree will have only 2^(k+1) + k + 1 nodes. We don't have to store almost half the nodes.
            //But, we have to do more work to calculate parent indices and child indices.
            //When a = 2^k, use the zero padding calculations since they are less computationally intensive.

        // For a = num_attributes, the copy padding tree will contain a + ceil(a/2) + ceil(ceil(a/2)/2) + ... + 1 nodes
        
        let mut summand = num_attributes;
        let mut total = 0;
        while summand > 1 {
            total += summand;
            summand = (summand + 1) / 2; // integer ceiling division
        }
        total
    }

    pub fn get_parent_index_zero_padding(height: u16, index: u16) -> Result<u16, TreeIndexError> {
        let root_index = Self::root_index(height);
        if index == root_index {
            Err(TreeIndexError::RootHasNoParent)
        } else if index > root_index {
            Err(TreeIndexError::IndexOutOfBounds)
        } else {
            let parent = root_index - ((root_index - index) - 1)/2;
            Ok(parent)
        }
    }

    pub fn get_parent_index_copy_padding(index: u16, size_of_current_level: u16, first_index_of_current_level: u16) -> Result<u16, TreeIndexError> {
        if size_of_current_level <= 1 {
            Err(TreeIndexError::RootHasNoParent)
        } else if index - first_index_of_current_level > size_of_current_level {
            Err(TreeIndexError::IndexOutOfBounds)
        } else {
            Ok(1u16) //might not need this function idk yet.
        }
    }

    pub fn get_left_child_index_zero_padding(height: u16, index: u16) -> Result<u16, TreeIndexError> {
        let last_leaf_index = Self::last_leaf_index(height);
        let root_index = Self::root_index(height);

        if index > root_index {
            Err(TreeIndexError::IndexOutOfBounds)
        } else if index <= last_leaf_index {
            Err(TreeIndexError::LeafHasNoChildren)
        } else {
            let left_child = root_index - ((root_index - index) * 2 + 2);
            Ok(left_child)
        }
    }

    pub fn get_right_child_index_zero_padding(height: u16, index: u16) -> Result<u16, TreeIndexError> {
        let last_leaf_index = Self::last_leaf_index(height);
        let root_index = Self::root_index(height);

        if index > root_index {
            Err(TreeIndexError::IndexOutOfBounds)
        } else if index <= last_leaf_index {
            Err(TreeIndexError::LeafHasNoChildren)
        } else {
            let right_child = root_index - ((root_index - index) * 2 + 1);
            Ok(right_child)
        }
    }

    pub fn build_from_data(data: &[Vec<u8>], padding_scheme: PaddingScheme, tree_storage_type: TreeStorageType) -> Self {
        match (padding_scheme, tree_storage_type) {
            (PaddingScheme::Zero, TreeStorageType::StoredLeavesAndCalculatedHashes(_nodes)) => Self::build_zero_padded_full_tree_from_data(data),
            (PaddingScheme::Copy(a), TreeStorageType::StoredLeavesAndCalculatedHashes(_nodes)) => Self::build_copy_padded_full_tree_from_data(data),
            _ => panic!("This combination of padding scheme and tree storage type is not implemented yet"),
        }
    }

    fn build_copy_padded_full_tree_from_data(data: &[Vec<u8>]) -> Self {
        let num_attributes = data.len() as u16;
        let root_index = Self::root_index_copy_padding(num_attributes);
        let height: u16 = (num_attributes as f64).log2().ceil() as u16 + 1;

        let mut all_nodes: Vec<Vec<u8>> = Vec::with_capacity((root_index + 1) as usize);

        for current_index in 0..num_attributes {
            let mut hasher = Sha3_256::new();
            hasher.update(&data[current_index as usize]);
            all_nodes.push(hasher.finalize().to_vec());
        }

        let mut last_filled_index_of_previous_level: u16 = num_attributes - 1;
        let mut size_of_current_level: u16 = (num_attributes + 1) / 2;
        let mut next_left_child_index: u16 = 0;
        let mut current_index = num_attributes;

        for _ in 1..height {
            for __ in 0..size_of_current_level {
                let left_child_index: u16 = next_left_child_index;
                let right_child_index: u16 = if left_child_index + 1 <= last_filled_index_of_previous_level {
                    left_child_index + 1
                } else {
                    left_child_index // duplicate the last node if odd number of nodes
                };

                let left_child_bytes: &[u8] = &all_nodes[left_child_index as usize];
                let right_child_bytes: &[u8] = &all_nodes[right_child_index as usize];

                let mut hasher = Sha3_256::new();
                hasher.update(left_child_bytes);
                hasher.update(right_child_bytes);
                all_nodes.push(hasher.finalize().to_vec());
                current_index += 1;

                next_left_child_index += 2;
            }

            last_filled_index_of_previous_level = current_index - 1;
            next_left_child_index = last_filled_index_of_previous_level - size_of_current_level + 1;
            size_of_current_level = (size_of_current_level + 1) / 2;
        }

        let root: Vec<u8> = all_nodes[root_index as usize].clone();

        MerkleAVC {
            root,
            height,
            num_attributes,
            padding_scheme: PaddingScheme::Copy(vec![]), // the associated vector will contain the precomputed indices of each level, maybe.
            stored_values: TreeStorageType::StoredLeavesAndCalculatedHashes(all_nodes),
        }

    }

    fn build_zero_padded_full_tree_from_data(data: &[Vec<u8>]) -> Self {
        let num_attributes: u16 = data.len() as u16;
        let height: u16 = (num_attributes as f64).log2().ceil() as u16 + 1;
        let root_index = Self::root_index(height);
        let last_leaf_index = num_attributes - 1;

        let mut all_nodes: Vec<Vec<u8>> = Vec::with_capacity((root_index + 1) as usize);

        for curr_ind in 0..=root_index {
            if curr_ind < num_attributes {
                let mut hasher = Sha3_256::new();
                hasher.update(&data[curr_ind as usize]);
                all_nodes.push(hasher.finalize().to_vec());
            } else if curr_ind <= last_leaf_index{ 
                let mut hasher = Sha3_256::new();
                hasher.update(&[0u8]); //zero padding
                all_nodes.push(hasher.finalize().to_vec());
            } else {
                // shouldn't panic because curr_ind is guaranteed to be an internal node here 
                let left_child_index: u16 = Self::get_left_child_index_zero_padding(height, curr_ind).unwrap();
                let right_child_index: u16 = Self::get_right_child_index_zero_padding(height, curr_ind).unwrap();

                let left_child_bytes: &[u8] = &all_nodes[left_child_index as usize];
                let right_child_bytes: &[u8] = &all_nodes[right_child_index as usize];

                let mut hasher = Sha3_256::new();
                hasher.update(left_child_bytes);
                hasher.update(right_child_bytes);
                all_nodes.push(hasher.finalize().to_vec()); 
                // so the hasher owns its own copy of the vector. to_vec clones it since we want all_nodes 
                // to own its own copy. Is there some way to avoid this? This is a cheap clone so dw ig.
            }
        }

        // we want the merkle tree to own the root as a copy as well methinks 
        let root: Vec<u8> = all_nodes[root_index as usize].clone();

        MerkleAVC {
            root,
            height,
            num_attributes,
            padding_scheme: PaddingScheme::Zero,
            stored_values: TreeStorageType::StoredLeavesAndCalculatedHashes(all_nodes),
        }

    }

    fn generate_copath_for_copy_padded_full_tree(&self, index: u16) -> Vec<Vec<u8>> {
        if index >= self.num_attributes {
            panic!("Index out of bounds");
        }

        let mut copath: Vec<Vec<u8>> = Vec::with_capacity((self.height - 1) as usize);
        let mut current_index = index;

        let mut first_index_of_current_level: u16 = self.num_attributes;
        let mut size_of_current_level: u16 = (self.num_attributes + 1) / 2;
        let mut current_index = self.num_attributes;

        for _ in 1..self.height {
            println!("Current level size: {}", size_of_current_level);
            println!("Current index: {}", current_index);
            println!("first_index_of_current_level: {}", first_index_of_current_level);
            
            let sibling_index = if current_index == first_index_of_current_level + size_of_current_level {
                current_index // duplicate the last node if odd number of nodes
            } else {
                (current_index - first_index_of_current_level) ^ 1 + first_index_of_current_level
            };

            match &self.stored_values {
                TreeStorageType::StoredLeavesAndCalculatedHashes(all_nodes) => {
                    copath.push(all_nodes[sibling_index as usize].clone());
                },
                TreeStorageType::StoredLeaves(_) => {
                    panic!("This implementation requires all node hashes to be stored");
                },
            }

            first_index_of_current_level += size_of_current_level;
            current_index = Self::get_parent_index_copy_padding(current_index, size_of_current_level, first_index_of_current_level).unwrap(); 
            size_of_current_level = (size_of_current_level + 1) / 2;
            }

        copath
    }

    fn generate_copath_for_zero_padded_full_tree(&self, index: u16) -> Vec<Vec<u8>> {
        if index >= self.num_attributes {
            panic!("Index out of bounds");
        }

        let mut copath: Vec<Vec<u8>> = Vec::with_capacity((self.height - 1) as usize);
        let mut current_index = index;

        while current_index < Self::root_index(self.height) {
            let parent_index = Self::get_parent_index_zero_padding(self.height, current_index).unwrap(); 
            //won't panic because current_index is guaranteed to not be the root here
            let sibling_index = current_index ^ 1;

            match &self.stored_values {
                TreeStorageType::StoredLeavesAndCalculatedHashes(all_nodes) => {
                    copath.push(all_nodes[sibling_index as usize].clone());
                },
                TreeStorageType::StoredLeaves(_) => {
                    panic!("This implementation requires all node hashes to be stored");
                },
            }

            current_index = parent_index;
        }

        copath
    }

    fn verify_copath_for_copy_padded_full_tree(
        copath: &Vec<Vec<u8>>,
        root: &Vec<u8>,
        value: &Vec<u8>,
        index: u16,
        num_attributes: u16,
    ) -> bool {
        true // Implement verification logic
    }

    fn verify_copath_for_zero_padded_full_tree(
        copath: &Vec<Vec<u8>>,
        root: &Vec<u8>,
        value: &Vec<u8>,
        index: u16,
        height: u16,
    ) -> bool {
        if copath.len() != (height-1) as usize {
            println!("copath length: {}, expected: {}", copath.len(), (height-1) as usize);
            return false; //copath length must be height - 1
        }

        let mut computed_hash: Vec<u8> = {
            let mut hasher = Sha3_256::new();
            hasher.update(value);
            hasher.finalize().to_vec()
        };

        let mut current_index = index;

        for sibling_hash in copath {
            let mut hasher = Sha3_256::new();
            if current_index % 2 == 0 {
                // current node is a left child
                hasher.update(&computed_hash);
                hasher.update(&sibling_hash);
            } else {
                // current node is a right child
                hasher.update(&sibling_hash);
                hasher.update(&computed_hash);
            }
            computed_hash = hasher.finalize().to_vec(); // my previously owned vector is dropped here and a new one is copied in
            current_index = match Self::get_parent_index_zero_padding(height, current_index) {
                Ok(parent) => parent,
                Err(_) => return false, // should not happen if inputs are correct
            };
        }

        &computed_hash == root
    }


}

/// We want to implement abstract primitive traits for our merkle objects. Here is actually a
/// pretty good example. I forgot about this, but I used this library while implementing the last 
/// chapter of my thesis: https://github.com/facebook/winterfell/blob/main/crypto/src/merkle/mod.rs 
///
/// They have a vector commitment trait and a merkle tree that implements the trait as well. For
/// us, things are different because we need much more merkle diversity. Here is another crate: 
/// https://crates.io/crates/merkletree. This code was developed by the protocol labs guys. They 
/// are super good, but a classic case of research with no direction. The code is very rust
/// idiomatic and this is code that is incredibly memory efficient. I would look through it to see 
/// what types of patters they use and decisions they make. Our code will be much more readable
/// than this. Typically, the best place to start is adapting ideas from what is already out there. 
///
impl VectorCommitment for MerkleAVC {
    type Element = Vec<u8>;
    type PublicParams = ();
    type KeyMaterial = ();
    type Commitment = Vec<u8>;
    type Proof = Vec<Vec<u8>>; // copath hashes

    // we can think about this a bit more closely. In the case of hash-based schemes, because we
    // are in a symmetric key setting, this isn't always necessary. We should do the exercise of
    // looking at some 
    fn keygen(_security_param: usize) -> (Self::PublicParams, Self::KeyMaterial) {
        ((), ()) // I suppose we could use the security param to choose a hash function that achieves the appropriate security level
    }

    fn commit(vector: &[Self::Element], _key: &Self::KeyMaterial) -> Self::Commitment {
        Self::build_zero_padded_full_tree_from_data(vector).root 
        // this does a lot of work to build the whole tree just to return the root
        // maybe let's implement a method that solely computes the root from the leaves 
        // without storing the whole tree
    }

    fn open(
        index: usize,
        commitment: &Self::Commitment,
        vector: &[Self::Element],
        _key: &Self::KeyMaterial,
    ) -> Self::Proof {
        if index >= vector.len() {
            panic!("Index out of bounds");
        }
        Self::generate_copath_for_zero_padded_full_tree(
            &Self::build_zero_padded_full_tree_from_data(vector), //this is inefficient because it rebuilds the whole tree just to get the copath
            index as u16,
        )
    }

    fn verify(
        proof: &Self::Proof,
        commitment: &Self::Commitment,
        value: &Self::Element,
        index: usize,
        params: &Self::PublicParams,
    ) -> bool {
        true // Implement verification logic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parent_index_calculation() {
        let height = 4;

        // For height 4: root_index = 14
        // Parent of node 12 should be 14
        assert_eq!(MerkleAVC::get_parent_index_zero_padding(height, 12), Ok(14));

        // Parent of node 13 should be 14
        assert_eq!(MerkleAVC::get_parent_index_zero_padding(height, 13), Ok(14));

        // Parent of node 10 should be 13
        assert_eq!(MerkleAVC::get_parent_index_zero_padding(height, 10), Ok(13));

        // Parent of node 11 should be 13
        assert_eq!(MerkleAVC::get_parent_index_zero_padding(height, 11), Ok(13));
    }

    #[test]
    fn test_root_index_copy_padding() {
        // Test cases for various numbers of attributes
        let test_cases = vec![
            (2, 2),
            (5, 10),  // 5 attributes -> root at 10th index
        ];

        for (num_attributes, expected_nodes) in test_cases {
            assert_eq!(
                MerkleAVC::root_index_copy_padding(num_attributes),
                expected_nodes,
                "Failed for {} attributes",
                num_attributes
            );
        }
    }

    #[test]
    fn test_root_has_no_parent() {
        let height = 4;

        // Root index for height 3 is 14
        let result = MerkleAVC::get_parent_index_zero_padding(height, 14);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TreeIndexError::RootHasNoParent);
    }

    #[test]
    fn test_parent_index_out_of_bounds() {
        let height = 4;

        // Index 15 is out of bounds (root is 14)
        let result = MerkleAVC::get_parent_index_zero_padding(height, 15);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TreeIndexError::IndexOutOfBounds);
    }

    #[test]
    fn test_left_child_index_calculation() {
        let height = 4;

        // Left child of root (14) should be 12
        assert_eq!(MerkleAVC::get_left_child_index_zero_padding(height, 14), Ok(12));

        // Left child of node 13 should be 10
        assert_eq!(MerkleAVC::get_left_child_index_zero_padding(height, 13), Ok(10));

        // Left child of node 12 should be 8
        assert_eq!(MerkleAVC::get_left_child_index_zero_padding(height, 12), Ok(8));
    }

    #[test]
    fn test_right_child_index_calculation() {
        let height = 4;

        // Right child of root (14) should be 13
        assert_eq!(MerkleAVC::get_right_child_index_zero_padding(height, 14), Ok(13));

        // Right child of node 13 should be 11
        assert_eq!(MerkleAVC::get_right_child_index_zero_padding(height, 13), Ok(11));

        // Right child of node 12 should be 9
        assert_eq!(MerkleAVC::get_right_child_index_zero_padding(height, 12), Ok(9));
    }

    #[test]
    fn test_leaf_has_no_children() {
        let height = 4;

        // For height 3: last leaf index = 7
        // Leaf nodes should have no children
        let left_result = MerkleAVC::get_left_child_index_zero_padding(height, 5);
        assert!(left_result.is_err());
        assert_eq!(left_result.unwrap_err(), TreeIndexError::LeafHasNoChildren);

        let right_result = MerkleAVC::get_right_child_index_zero_padding(height, 5);
        assert!(right_result.is_err());
        assert_eq!(right_result.unwrap_err(), TreeIndexError::LeafHasNoChildren);
    }

    #[test]
    fn test_child_index_out_of_bounds() {
        let height = 4;

        // Index 15 is out of bounds (root is 14)
        let left_result = MerkleAVC::get_left_child_index_zero_padding(height, 15);
        assert!(left_result.is_err());
        assert_eq!(left_result.unwrap_err(), TreeIndexError::IndexOutOfBounds);

        let right_result = MerkleAVC::get_right_child_index_zero_padding(height, 15);
        assert!(right_result.is_err());
        assert_eq!(right_result.unwrap_err(), TreeIndexError::IndexOutOfBounds);
    }

    #[test]
    fn test_build_zero_padded_tree_basic() {
        // Build a tree with 3 attributes
        let data = vec![
            vec![1u8, 2u8],
            vec![3u8, 4u8],
            vec![5u8, 6u8],
        ];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Tree should have height 3 (ceil(log2(3)) = 2, so 4 leaves)
        assert_eq!(tree.height, 3);
        assert_eq!(tree.num_attributes, 3);
        assert!(!tree.root.is_empty());

        // Verify tree structure is StoredLeavesAndCalculatedHashes
        match tree.stored_values {
            TreeStorageType::StoredLeavesAndCalculatedHashes(ref nodes) => {
                // For height 3: root_index = 2^3 - 2 = 6
                // Should have 7 nodes (indices 0-6)
                assert_eq!(nodes.len(), 7);
            }
            _ => panic!("Expected StoredLeavesAndCalculatedHashes"),
        }
    }

        #[test]
    fn test_build_copy_padded_tree_basic() {
        // Build a tree with 3 attributes
        let data = vec![
            vec![1u8, 2u8],
            vec![3u8, 4u8],
            vec![5u8, 6u8],
            vec![7u8, 8u8],
            vec![9u8, 10u8],
        ];

        let tree = MerkleAVC::build_copy_padded_full_tree_from_data(&data);

        // Tree should have height 3 (ceil(log2(3)) = 2, so 4 leaves)
        assert_eq!(tree.height, 4);
        assert_eq!(tree.num_attributes, 5);
        assert!(!tree.root.is_empty());

        // Verify tree structure is StoredLeavesAndCalculatedHashes
        match tree.stored_values {
            TreeStorageType::StoredLeavesAndCalculatedHashes(ref nodes) => {
                // For height 3: root_index = 2^3 - 2 = 6
                // Should have 7 nodes (indices 0-6)
                assert_eq!(nodes.len(), 11);
            }
            _ => panic!("Expected StoredLeavesAndCalculatedHashes"),
        }
    }

    #[test]
    fn test_build_zero_padded_tree_power_of_two() {
        // Build a tree with exactly 4 attributes (power of 2)
        let data = vec![
            vec![1u8],
            vec![2u8],
            vec![3u8],
            vec![4u8],
        ];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Should have height 3
        assert_eq!(tree.height, 3);
        assert_eq!(tree.num_attributes, 4);
    }

    #[test]
    fn test_build_zero_padded_tree_single_element() {
        let data = vec![vec![42u8]];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Single element should have height 1
        assert_eq!(tree.height, 1);
        assert_eq!(tree.num_attributes, 1);

        // Root should be hash of the single element
        let mut hasher = Sha3_256::new();
        hasher.update(&[42u8]);
        let expected_root = hasher.finalize().to_vec();
        assert_eq!(tree.root, expected_root);
    }

    #[test]
    fn test_generate_copath_first_leaf() {
        // Build a simple tree with 4 leaves
        let data = vec![
            vec![1u8],
            vec![2u8],
            vec![3u8],
            vec![4u8],
        ];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Generate copath for first leaf (index 0)
        let copath = tree.generate_copath_for_zero_padded_full_tree(0);

        // For height 3, copath should have length 2 (height - 1)
        assert_eq!(copath.len(), 2);

        // Each element should be a hash
        for hash in &copath {
            assert!(!hash.is_empty());
        }
    }

    #[test]
    fn test_generate_copath_middle_leaf() {
        let data = vec![
            vec![1u8],
            vec![2u8],
            vec![3u8],
            vec![4u8],
        ];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Generate copath for middle leaf (index 2)
        let copath = tree.generate_copath_for_zero_padded_full_tree(2);

        assert_eq!(copath.len(), 2);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_generate_copath_out_of_bounds() {
        let data = vec![vec![1u8], vec![2u8]];
        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Try to generate copath for index beyond num_attributes
        tree.generate_copath_for_zero_padded_full_tree(5);
    }

    #[test]
    fn test_verify_copath_valid() {
        // Build a tree
        let data = vec![
            vec![10u8, 20u8],
            vec![30u8, 40u8],
            vec![50u8, 60u8],
        ];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Generate copath for index 1
        let copath = tree.generate_copath_for_zero_padded_full_tree(1);

        // Verify the copath with the correct value
        let is_valid = MerkleAVC::verify_copath_for_zero_padded_full_tree(
            &copath,
            &tree.root,
            &data[1],
            1,
            tree.height,
        );

        assert!(is_valid, "Valid copath should verify successfully");
    }

    #[test]
    fn test_verify_copath_invalid_value() {
        let data = vec![
            vec![10u8],
            vec![20u8],
            vec![30u8],
        ];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Generate copath for index 0
        let copath = tree.generate_copath_for_zero_padded_full_tree(0);

        // Try to verify with wrong value
        let wrong_value = vec![99u8];
        let is_valid = MerkleAVC::verify_copath_for_zero_padded_full_tree(
            &copath,
            &tree.root,
            &wrong_value,
            0,
            tree.height,
        );

        assert!(!is_valid, "Invalid value should fail verification");
    }

    #[test]
    fn test_verify_copath_wrong_length() {
        let data = vec![vec![1u8], vec![2u8]];
        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Create copath with wrong length
        let wrong_copath = vec![vec![0u8; 32]]; // Wrong length for height 1 tree

        let is_valid = MerkleAVC::verify_copath_for_zero_padded_full_tree(
            &wrong_copath,
            &tree.root,
            &vec![1u8],
            0,
            tree.height,
        );

        assert!(!is_valid, "Wrong copath length should fail verification");
    }

    #[test]
    fn test_copath_roundtrip_all_leaves() {
        // Test that we can generate and verify copath for every leaf
        let data = vec![
            vec![100u8],
            vec![200u8],
            vec![50u8],
            vec![150u8],
            vec![250u8],
        ];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        // Verify copath for each leaf
        for (index, value) in data.iter().enumerate() {
            let copath = tree.generate_copath_for_zero_padded_full_tree(index as u16);


            let is_valid: bool = MerkleAVC::verify_copath_for_zero_padded_full_tree(
                &copath,
                &tree.root,
                value,
                index as u16,
                tree.height,
            );

            assert!(is_valid, "Copath for leaf {} should verify", index);
        }
    }

    #[test]
    fn test_verify_copath_wrong_root() {
        let data = vec![vec![1u8], vec![2u8]];
        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(&data);

        let copath = tree.generate_copath_for_zero_padded_full_tree(0);

        // Use wrong root
        let wrong_root = vec![0u8; 32];
        let is_valid = MerkleAVC::verify_copath_for_zero_padded_full_tree(
            &copath,
            &wrong_root,
            &data[0],
            0,
            tree.height,
        );

        assert!(!is_valid, "Wrong root should fail verification");
    }
}
