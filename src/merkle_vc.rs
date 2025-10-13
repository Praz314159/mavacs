use crate::vector_commitment::VectorCommitment;
//use std::hash::{Hasher, Hash::{Digest, Hasher}};
use sha3::{Digest, Sha3_256};

pub enum PaddingScheme {
    Zero,
    Copy,
    Random(u8),
}

pub enum TreeStorageType {
    StoredLeaves(Vec<Vec<u8>>),
    StoredLeavesAndCalculatedHashes(Vec<Vec<u8>>),
}

pub struct MerkleAVC {
    pub root: Vec<u8>,
    pub height: u16,
    pub num_attributes: u16,
    pub padding_scheme: PaddingScheme,
    //hash: Hasher,
    pub stored_values: TreeStorageType,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TreeIndexError {
    RootHasNoParent,
    IndexOutOfBounds,
    LeafHasNoChildren,
}

impl MerkleAVC {
    const fn root_index(height: u16) -> u16 {
        2_u16.pow(height as u32) - 2
    }

    const fn last_leaf_index(height: u16) -> u16 {
        2_u16.pow(height as u32 - 1) - 1
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

    fn build_from_data(data: Vec<Vec<u8>>, padding_scheme: PaddingScheme, tree_storage_type: TreeStorageType) -> Self {
        match (padding_scheme, tree_storage_type) {
            (PaddingScheme::Zero, TreeStorageType::StoredLeavesAndCalculatedHashes(nodes)) => Self::build_zero_padded_full_tree_from_data(data),
            _ => unimplemented!("Only zero padding on a fully stored tree is implemented"),
        }
    }

    fn build_zero_padded_full_tree_from_data(data: Vec<Vec<u8>>) -> Self {
        let num_attributes: u16 = data.len() as u16;
        let height: u16 = (num_attributes as f64).log2().ceil() as u16 + 1;
        let root_index = Self::root_index(height);
        let last_leaf_index = Self::last_leaf_index(height);

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
                let left_child_index: u16 = Self::get_left_child_index_zero_padding(height, curr_ind).unwrap(); //shouldn't panic because curr_ind is guaranteed to be an internal node here
                let right_child_index: u16 = Self::get_right_child_index_zero_padding(height, curr_ind).unwrap();

                let left_child_bytes: &[u8] = &all_nodes[left_child_index as usize];
                let right_child_bytes: &[u8] = &all_nodes[right_child_index as usize];

                let mut hasher = Sha3_256::new();
                hasher.update(left_child_bytes);
                hasher.update(right_child_bytes);
                all_nodes.push(hasher.finalize().to_vec()); // so the hasher owns its own copy of the vector. to_vec clones it since we want all_nodes to own its own copy. Is there some way to avoid this? This is a cheap clone so dw ig.
            }
        }

        let root: Vec<u8> = all_nodes[root_index as usize].clone(); //we want the merkle tree to own the root as a copy as well methinks

        MerkleAVC {
            root,
            height,
            num_attributes,
            padding_scheme: PaddingScheme::Zero,
            stored_values: TreeStorageType::StoredLeavesAndCalculatedHashes(all_nodes),
        }

    }

    fn generate_copath_for_zero_padded_full_tree(&self, index: u16) -> Vec<Vec<u8>> {
        if index >= self.num_attributes {
            panic!("Index out of bounds");
        }

        let mut copath: Vec<Vec<u8>> = Vec::with_capacity((self.height - 1) as usize);
        let mut current_index = index;

        while current_index < Self::root_index(self.height) {
            let parent_index = Self::get_parent_index_zero_padding(self.height, current_index).unwrap(); //won't panic because current_index is guaranteed to not be the root here
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

impl VectorCommitment for MerkleAVC {
    type Element = Vec<u8>;
    type PublicParams = ();
    type KeyMaterial = ();
    type Commitment = Vec<u8>;
    type Proof = Vec<Vec<u8>>; // copath hashes

    fn keygen(_security_param: usize) -> (Self::PublicParams, Self::KeyMaterial) {
        ((), ()) // I suppose we could use the security param to choose a hash function that achieves the appropriate security level
    }

    fn commit(vector: &[Self::Element], _key: &Self::KeyMaterial) -> Self::Commitment {
        Self::build_zero_padded_full_tree_from_data(vector.to_vec()).root //this does a lot of work to 
                                                                                                //build the whole tree and clone it in to_vec just to return the root
                                                                                                //maybe let's implement a method that solely computes the root
                                                                                                //from the leaves without storing the whole tree
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
            &Self::build_zero_padded_full_tree_from_data(vector.to_vec()), //this is inefficient because it rebuilds the whole tree just to get the copath
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

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data.clone());

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
    fn test_build_zero_padded_tree_power_of_two() {
        // Build a tree with exactly 4 attributes (power of 2)
        let data = vec![
            vec![1u8],
            vec![2u8],
            vec![3u8],
            vec![4u8],
        ];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data);

        // Should have height 3
        assert_eq!(tree.height, 3);
        assert_eq!(tree.num_attributes, 4);
    }

    #[test]
    fn test_build_zero_padded_tree_single_element() {
        let data = vec![vec![42u8]];

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data);

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

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data);

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

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data);

        // Generate copath for middle leaf (index 2)
        let copath = tree.generate_copath_for_zero_padded_full_tree(2);

        assert_eq!(copath.len(), 2);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_generate_copath_out_of_bounds() {
        let data = vec![vec![1u8], vec![2u8]];
        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data);

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

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data.clone());

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

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data);

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
        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data);

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

        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data.clone());

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
        let tree = MerkleAVC::build_zero_padded_full_tree_from_data(data.clone());

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