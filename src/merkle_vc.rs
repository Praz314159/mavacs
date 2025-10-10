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
    pub stored_values: TreeStorageType
}

impl MerkleAVC {
    pub fn get_parent_index_for_full_mavc_with_zero_padding(&self, index: u16) -> Result<u16, String> {
        let root_index: u16 = 2_u16.pow(self.height as u32 + 1_u32) - 2;
        if index == root_index {
            Err("Root node has no parent".to_string())
        } else if index > root_index { 
            Err("Index out of bounds".to_string()) 
        } else {
            let parent: u16 = root_index - ((root_index - index) - 1)/2;
            Ok(parent)
        }        
    }

    pub fn get_left_child_index_for_full_mavc_with_zero_padding(&self, index: u16) -> Result<u16, String> {
        let last_leaf_index: u16 = 2_u16.pow(self.height as u32) - 1;
        let root_index: u16 = 2_u16.pow(self.height as u32 + 1_u32) - 2;

        if index > root_index {
            Err("Index out of bounds".to_string())
        } else if index <= last_leaf_index {
            Err("Leaf node has no children".to_string())
        } else {
            let left_child = root_index - ((root_index - index) * 2 + 2);
            Ok(left_child)
        }        
    }

    pub fn get_right_child_index_for_full_mavc_with_zero_padding(&self, index: u16) -> Result<u16, String> {
        let last_leaf_index: u16 = 2_u16.pow(self.height as u32) - 1;
        let root_index: u16 = 2_u16.pow(self.height as u32 + 1_u32) - 2;

        if index > root_index {
            Err("Index out of bounds".to_string())
        } else if index <= last_leaf_index {
            Err("Leaf node has no children".to_string())
        } else {
            let right_child = root_index - ((root_index - index) * 2 + 1);
            Ok(right_child)
        }        
    }

    fn build_full_mavc_with_zero_padding_from_vector_of_bytes(data: Vec<Vec<u8>>) -> Self {
        let num_attributes: u16 = data.len() as u16;
        let height: u16 = (num_attributes as f64).log2().ceil() as u16;
        let root_index: u16 = 2_u16.pow(height as u32 + 1_u32) - 2;

        let mut all_nodes: Vec<Vec<u8>> = vec![];

        for curr_ind in 0..=root_index {
            if curr_ind < num_attributes {
                let mut hasher = Sha3_256::new();
                hasher.update(data[curr_ind as usize].clone()); //don't wanna clone here. Pass by reference.
                all_nodes.push(hasher.finalize().to_vec());
            } else {
                let concat_bytes = vec![]; //obtain by concatenating left and right child hashes
                let mut hasher = Sha3_256::new();
                hasher.update(concat_bytes);
                all_nodes.push(hasher.finalize().to_vec());
            }
        }


        let root: Vec<u8> = all_nodes[root_index as usize].clone(); //TODO: don't wanna clone here. Maybe assign root when detected in for loop.

        MerkleAVC {
            root,
            height: 0,  // Calculate properly
            num_attributes: data.len() as u16,
            padding_scheme: PaddingScheme::Zero,
            stored_values: TreeStorageType::StoredLeavesAndCalculatedHashes(all_nodes),
        }

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
        Self::build_full_mavc_with_zero_padding_from_vector_of_bytes(vector.to_vec()).root
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
        vec![] // Implement proof generation logic
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

    fn create_test_tree(height: u16) -> MerkleAVC {
        MerkleAVC {
            root: vec![],
            height,
            num_attributes: 5,
            padding_scheme: PaddingScheme::Zero,
            stored_values: TreeStorageType::StoredLeaves(vec![]),
        }
    }

    #[test]
    fn test_parent_index_calculation() {
        let tree = create_test_tree(3);

        // For height 3: root_index = 14
        // Parent of node 12 should be 14
        assert_eq!(tree.get_parent_index_for_full_mavc_with_zero_padding(12), Ok(14));

        // Parent of node 13 should be 14
        assert_eq!(tree.get_parent_index_for_full_mavc_with_zero_padding(13), Ok(14));

        // Parent of node 10 should be 13
        assert_eq!(tree.get_parent_index_for_full_mavc_with_zero_padding(10), Ok(13));

        // Parent of node 11 should be 13
        assert_eq!(tree.get_parent_index_for_full_mavc_with_zero_padding(11), Ok(13));
    }

    #[test]
    fn test_root_has_no_parent() {
        let tree = create_test_tree(3);

        // Root index for height 3 is 14
        let result = tree.get_parent_index_for_full_mavc_with_zero_padding(14);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Root node has no parent");
    }

    #[test]
    fn test_parent_index_out_of_bounds() {
        let tree = create_test_tree(3);

        // Index 15 is out of bounds (root is 14)
        let result = tree.get_parent_index_for_full_mavc_with_zero_padding(15);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Index out of bounds");
    }

    #[test]
    fn test_left_child_index_calculation() {
        let tree = create_test_tree(3);

        // Left child of root (14) should be 12
        assert_eq!(tree.get_left_child_index_for_full_mavc_with_zero_padding(14), Ok(12));

        // Left child of node 13 should be 10
        assert_eq!(tree.get_left_child_index_for_full_mavc_with_zero_padding(13), Ok(10));

        // Left child of node 12 should be 8
        assert_eq!(tree.get_left_child_index_for_full_mavc_with_zero_padding(12), Ok(8));
    }

    #[test]
    fn test_right_child_index_calculation() {
        let tree = create_test_tree(3);

        // Right child of root (14) should be 13
        assert_eq!(tree.get_right_child_index_for_full_mavc_with_zero_padding(14), Ok(13));

        // Right child of node 13 should be 11
        assert_eq!(tree.get_right_child_index_for_full_mavc_with_zero_padding(13), Ok(11));

        // Right child of node 12 should be 9
        assert_eq!(tree.get_right_child_index_for_full_mavc_with_zero_padding(12), Ok(9));
    }

    #[test]
    fn test_leaf_has_no_children() {
        let tree = create_test_tree(3);

        // For height 3: last leaf index = 7
        // Leaf nodes should have no children
        let left_result = tree.get_left_child_index_for_full_mavc_with_zero_padding(5);
        assert!(left_result.is_err());
        assert_eq!(left_result.unwrap_err(), "Leaf node has no children");

        let right_result = tree.get_right_child_index_for_full_mavc_with_zero_padding(5);
        assert!(right_result.is_err());
        assert_eq!(right_result.unwrap_err(), "Leaf node has no children");
    }

    #[test]
    fn test_child_index_out_of_bounds() {
        let tree = create_test_tree(3);

        // Index 15 is out of bounds (root is 14)
        let left_result = tree.get_left_child_index_for_full_mavc_with_zero_padding(15);
        assert!(left_result.is_err());
        assert_eq!(left_result.unwrap_err(), "Index out of bounds");

        let right_result = tree.get_right_child_index_for_full_mavc_with_zero_padding(15);
        assert!(right_result.is_err());
        assert_eq!(right_result.unwrap_err(), "Index out of bounds");
    }
}