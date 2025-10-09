use crate::vector_commitment::VectorCommitment;
//use std::hash::{Hasher, Hash::{Digest, Hasher}};
use sha3::{Digest, Sha3_256};

enum PaddingScheme {
    Zero,
    Copy,
    Random(u8),
}

enum TreeStorageType {
    StoredLeaves(Vec<Vec<u8>>),
    StoredLeavesAndCalculatedHashes(Vec<Vec<u8>>),
}

struct MerkleAVC {
    root: Vec<u8>,
    height: u16,
    num_attributes: u16,
    padding_scheme: PaddingScheme,
    //hash: Hasher,
    stored_values: TreeStorageType
}

impl MerkleAVC {
    fn build_full_mavc_with_zero_padding_from_vector_of_bytes(data: Vec<Vec<u8>>) -> Self {
        let num_attributes: u16 = data.len() as u16;
        let mut all_nodes: Vec<Vec<u8>> = vec![];

        for bytes in data.iter() {
            let mut hasher = Sha3_256::new();
            hasher.update(bytes);
            all_nodes.push(hasher.finalize().to_vec());
        }
        let root = all_nodes[0].clone(); // Placeholder, compute the actual root

        MerkleAVC {
            root,
            height: 0,  // Calculate properly
            num_attributes: data.len() as u16,
            padding_scheme: PaddingScheme::Zero,
            stored_values: TreeStorageType::StoredLeavesAndCalculatedHashes(vec![]),
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