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
    Copy, // the associated vector will contain the precomputed indices of each level.
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

    pub(crate) const fn root_index_copy_padding(num_attributes: u16) -> u16 {
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

    pub(crate) fn height_copy_padding(num_attributes: u16) -> u16 {
        (num_attributes as f64).log2().ceil() as u16 + 1
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
        } else if index < first_index_of_current_level || index - first_index_of_current_level > size_of_current_level {
            Err(TreeIndexError::IndexOutOfBounds)
        } else {
            let parent = (index - first_index_of_current_level) / 2 + first_index_of_current_level + size_of_current_level;
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

    pub fn build_from_data(data: &[Vec<u8>], padding_scheme: PaddingScheme, tree_storage_type: TreeStorageType) -> Self {
        match (padding_scheme, tree_storage_type) {
            (PaddingScheme::Zero, TreeStorageType::StoredLeavesAndCalculatedHashes(_nodes)) => Self::build_zero_padded_full_tree_from_data(data),
            (PaddingScheme::Copy, TreeStorageType::StoredLeavesAndCalculatedHashes(_nodes)) => Self::build_copy_padded_full_tree_from_data(data),
            _ => panic!("This combination of padding scheme and tree storage type is not implemented yet"),
        }
    }

    pub(crate) fn build_copy_padded_full_tree_from_data(data: &[Vec<u8>]) -> Self {
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
            padding_scheme: PaddingScheme::Copy,
            stored_values: TreeStorageType::StoredLeavesAndCalculatedHashes(all_nodes),
        }

    }

    pub(crate) fn build_zero_padded_full_tree_from_data(data: &[Vec<u8>]) -> Self {
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

    pub(crate) fn generate_copath_for_copy_padded_full_tree(&self, index: u16) -> Result<Vec<Vec<u8>>, TreeIndexError> {
        if index >= self.num_attributes {
            return Err(TreeIndexError::IndexOutOfBounds);
        }

        let mut copath: Vec<Vec<u8>> = Vec::with_capacity((self.height - 1) as usize);

        let mut first_index_of_current_level: u16 = 0;
        let mut size_of_current_level: u16 = self.num_attributes;
        let mut current_index = index;

        for _ in 1..self.height {
            
            let sibling_index = if current_index == first_index_of_current_level + size_of_current_level - 1 && size_of_current_level % 2 == 1 {
                current_index // duplicate the last node if odd number of nodes
            } else {
                ((current_index - first_index_of_current_level) ^ 1) + first_index_of_current_level
            };

            match &self.stored_values {
                TreeStorageType::StoredLeavesAndCalculatedHashes(all_nodes) => {
                    copath.push(all_nodes[sibling_index as usize].clone());
                },
                TreeStorageType::StoredLeaves(_) => {
                    panic!("This implementation requires all node hashes to be stored");
                },
            }

            current_index = Self::get_parent_index_copy_padding(current_index, size_of_current_level, first_index_of_current_level).unwrap(); 
            first_index_of_current_level += size_of_current_level; 
            size_of_current_level = (size_of_current_level + 1) / 2;
            }

        Ok(copath)
    }

    pub(crate) fn generate_copath_for_zero_padded_full_tree(&self, index: u16) -> Result<Vec<Vec<u8>>, TreeIndexError> {
        if index >= self.num_attributes {
            return Err(TreeIndexError::IndexOutOfBounds);
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

        Ok(copath)
    }

    pub(crate) fn verify_copath_for_copy_padded_full_tree(
        copath: &Vec<Vec<u8>>,
        root: &Vec<u8>,
        value: &Vec<u8>,
        index: u16,
        num_attributes: u16,
    ) -> bool {
        let height = Self::height_copy_padding(num_attributes);

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
        let mut first_index_of_current_level: u16 = 0;
        let mut size_of_current_level: u16 = num_attributes;

        for sibling_hash in copath {
            let mut hasher = Sha3_256::new();
            if (current_index - first_index_of_current_level) % 2 == 0 {
                // current node is a left child
                hasher.update(&computed_hash);
                hasher.update(&sibling_hash);
            } else {
                // current node is a right child
                hasher.update(&sibling_hash);
                hasher.update(&computed_hash);
            }
            computed_hash = hasher.finalize().to_vec(); // my previously owned vector is dropped here and a new one is copied in

            current_index = match Self::get_parent_index_copy_padding(current_index, size_of_current_level, first_index_of_current_level) {
                Ok(parent) => parent,
                Err(_) => return false, // should not happen if inputs are correct
            };

            first_index_of_current_level += size_of_current_level;
            size_of_current_level = (size_of_current_level + 1) / 2;
        }
        &computed_hash == root
    }

    pub(crate) fn verify_copath_for_zero_padded_full_tree(
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
        ).unwrap()
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
