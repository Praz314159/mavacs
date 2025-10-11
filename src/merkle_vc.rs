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
        2_u16.pow(height as u32 + 1) - 2
    }

    const fn last_leaf_index(height: u16) -> u16 {
        2_u16.pow(height as u32) - 1
    }

    pub fn get_parent_index_for_full_mavc_with_zero_padding(height: u16, index: u16) -> Result<u16, TreeIndexError> {
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

    pub fn get_left_child_index_for_full_mavc_with_zero_padding(height: u16, index: u16) -> Result<u16, TreeIndexError> {
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

    pub fn get_right_child_index_for_full_mavc_with_zero_padding(height: u16, index: u16) -> Result<u16, TreeIndexError> {
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

    fn build_full_mavc_with_zero_padding_from_vector_of_bytes(data: Vec<Vec<u8>>) -> Self {
        let num_attributes: u16 = data.len() as u16;
        let height: u16 = (num_attributes as f64).log2().ceil() as u16;
        let root_index = Self::root_index(height);
        let last_leaf_index = Self::last_leaf_index(height);

        let mut all_nodes: Vec<Vec<u8>> = vec![];
        
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
                let left_child_index: u16 = Self::get_left_child_index_for_full_mavc_with_zero_padding(height, curr_ind).unwrap(); //shouldn't panic because curr_ind is guaranteed to be an internal node here
                let right_child_index: u16 = Self::get_right_child_index_for_full_mavc_with_zero_padding(height, curr_ind).unwrap();

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

    fn generate_attribute_copath_for_full_mavc_with_zero_padding(&self, index: u16) -> Vec<Vec<u8>> {
        if index >= self.num_attributes {
            panic!("Index out of bounds");
        }

        let mut copath: Vec<Vec<u8>> = Vec::with_capacity(self.height as usize);
        let mut current_index = index;

        for _ in 0..(self.height - 1) {
            let parent_index = Self::get_parent_index_for_full_mavc_with_zero_padding(self.height, current_index).unwrap(); //shouldn't panic because current_index is guaranteed to not be the root here
            let sibling_index = current_index ^ 1; //sibling index is current_index with last bit flipped

            match &self.stored_values {
                TreeStorageType::StoredLeavesAndCalculatedHashes(all_nodes) => {
                    copath.push(all_nodes[sibling_index as usize].clone());  //copath will own its own copy of the sibling hash
                },
                TreeStorageType::StoredLeaves(_) => {
                    panic!("This implementation requires all node hashes to be stored");
                },
            }

            current_index = parent_index;
        }

        copath
    }


    fn verify_attribute_copath_for_full_mavc_with_zero_padding(
        copath: &Vec<Vec<u8>>,
        root: &Vec<u8>,
        value: &Vec<u8>,
        index: u16,
        height: u16,
    ) -> bool {
        if copath.len() != (height - 1) as usize {
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
            current_index = match Self::get_parent_index_for_full_mavc_with_zero_padding(height, current_index) {
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
        Self::build_full_mavc_with_zero_padding_from_vector_of_bytes(vector.to_vec()).root //this does a lot of work to 
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
        Self::generate_attribute_copath_for_full_mavc_with_zero_padding(
            &Self::build_full_mavc_with_zero_padding_from_vector_of_bytes(vector.to_vec()), //this is inefficient because it rebuilds the whole tree just to get the copath
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
        let height = 3;

        // For height 3: root_index = 14
        // Parent of node 12 should be 14
        assert_eq!(MerkleAVC::get_parent_index_for_full_mavc_with_zero_padding(height, 12), Ok(14));

        // Parent of node 13 should be 14
        assert_eq!(MerkleAVC::get_parent_index_for_full_mavc_with_zero_padding(height, 13), Ok(14));

        // Parent of node 10 should be 13
        assert_eq!(MerkleAVC::get_parent_index_for_full_mavc_with_zero_padding(height, 10), Ok(13));

        // Parent of node 11 should be 13
        assert_eq!(MerkleAVC::get_parent_index_for_full_mavc_with_zero_padding(height, 11), Ok(13));
    }

    #[test]
    fn test_root_has_no_parent() {
        let height = 3;

        // Root index for height 3 is 14
        let result = MerkleAVC::get_parent_index_for_full_mavc_with_zero_padding(height, 14);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TreeIndexError::RootHasNoParent);
    }

    #[test]
    fn test_parent_index_out_of_bounds() {
        let height = 3;

        // Index 15 is out of bounds (root is 14)
        let result = MerkleAVC::get_parent_index_for_full_mavc_with_zero_padding(height, 15);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TreeIndexError::IndexOutOfBounds);
    }

    #[test]
    fn test_left_child_index_calculation() {
        let height = 3;

        // Left child of root (14) should be 12
        assert_eq!(MerkleAVC::get_left_child_index_for_full_mavc_with_zero_padding(height, 14), Ok(12));

        // Left child of node 13 should be 10
        assert_eq!(MerkleAVC::get_left_child_index_for_full_mavc_with_zero_padding(height, 13), Ok(10));

        // Left child of node 12 should be 8
        assert_eq!(MerkleAVC::get_left_child_index_for_full_mavc_with_zero_padding(height, 12), Ok(8));
    }

    #[test]
    fn test_right_child_index_calculation() {
        let height = 3;

        // Right child of root (14) should be 13
        assert_eq!(MerkleAVC::get_right_child_index_for_full_mavc_with_zero_padding(height, 14), Ok(13));

        // Right child of node 13 should be 11
        assert_eq!(MerkleAVC::get_right_child_index_for_full_mavc_with_zero_padding(height, 13), Ok(11));

        // Right child of node 12 should be 9
        assert_eq!(MerkleAVC::get_right_child_index_for_full_mavc_with_zero_padding(height, 12), Ok(9));
    }

    #[test]
    fn test_leaf_has_no_children() {
        let height = 3;

        // For height 3: last leaf index = 7
        // Leaf nodes should have no children
        let left_result = MerkleAVC::get_left_child_index_for_full_mavc_with_zero_padding(height, 5);
        assert!(left_result.is_err());
        assert_eq!(left_result.unwrap_err(), TreeIndexError::LeafHasNoChildren);

        let right_result = MerkleAVC::get_right_child_index_for_full_mavc_with_zero_padding(height, 5);
        assert!(right_result.is_err());
        assert_eq!(right_result.unwrap_err(), TreeIndexError::LeafHasNoChildren);
    }

    #[test]
    fn test_child_index_out_of_bounds() {
        let height = 3;

        // Index 15 is out of bounds (root is 14)
        let left_result = MerkleAVC::get_left_child_index_for_full_mavc_with_zero_padding(height, 15);
        assert!(left_result.is_err());
        assert_eq!(left_result.unwrap_err(), TreeIndexError::IndexOutOfBounds);

        let right_result = MerkleAVC::get_right_child_index_for_full_mavc_with_zero_padding(height, 15);
        assert!(right_result.is_err());
        assert_eq!(right_result.unwrap_err(), TreeIndexError::IndexOutOfBounds);
    }
}