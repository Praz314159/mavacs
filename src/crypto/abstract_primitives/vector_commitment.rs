/// 
/// Traits for vector commitments 
///
///

pub trait VectorCommitment {
    type Element;
    type PublicParams;
    type KeyMaterial;
    type Commitment;
    type Proof;

    fn keygen(security_param: usize) -> (Self::PublicParams, Self::KeyMaterial);

    fn commit(
        vector: &[Self::Element], 
        key: &Self::KeyMaterial,
    ) -> Self::Commitment;

    fn open(
        index: usize,
        commitment: &Self::Commitment,
        vector: &[Self::Element],
        key: &Self::KeyMaterial,
    ) -> Self::Proof;

    fn verify(
        proof: &Self::Proof,
        commitment: &Self::Commitment,
        value: &Self::Element,
        index: usize,
        params: &Self::PublicParams,
    ) -> bool;
}

// TODO: extension of vector commitment trait for dynamic vector commitments
