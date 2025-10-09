/// Trait for cryptographic vector commitment schemes
///
/// A vector commitment allows committing to a vector of elements with a compact commitment,
/// and later proving that specific elements exist at specific indices without revealing
/// the entire vector.
///
/// This trait abstracts over different implementation strategies (e.g., Merkle trees,
/// KZG commitments, Pedersen commitments) while providing a uniform API for use in
/// verifiable anonymous credentials.
pub trait VectorCommitment {
    /// The type of elements in the vector (for attributes, this will be Vec<u8>)
    type Element;

    /// Public parameters generated during setup
    type PublicParams;

    /// Secret key material for the committer
    type KeyMaterial;

    /// The commitment to the vector
    type Commitment;

    /// Proof that an element exists at a specific index
    type Proof;

    /// Generate public parameters and key material
    ///
    /// # Arguments
    /// * `security_param` - Security parameter (e.g., 128, 256 for bits of security)
    ///
    /// # Returns
    /// Tuple of (public_params, key_material)
    fn keygen(security_param: usize) -> (Self::PublicParams, Self::KeyMaterial);

    /// Commit to a vector of elements
    ///
    /// Creates a binding commitment to the entire vector. The commitment should be
    /// compact (ideally constant size) and cryptographically bind to all elements
    /// and their positions.
    ///
    /// # Arguments
    /// * `vector` - The vector of elements to commit to
    /// * `key` - Secret key material from keygen
    ///
    /// # Returns
    /// A commitment binding to the entire vector
    fn commit(vector: &[Self::Element], key: &Self::KeyMaterial) -> Self::Commitment;

    /// Open the commitment at a specific index
    ///
    /// Generates a proof that demonstrates the value at a specific index in the
    /// committed vector. The proof should be verifiable without access to the
    /// full vector.
    ///
    /// # Arguments
    /// * `index` - The index to open
    /// * `commitment` - The commitment to the vector
    /// * `vector` - The full vector
    /// * `key` - Secret key material from keygen
    ///
    /// # Returns
    /// A proof that vector[index] has the claimed value
    fn open(
        index: usize,
        commitment: &Self::Commitment,
        vector: &[Self::Element],
        key: &Self::KeyMaterial,
    ) -> Self::Proof;

    /// Verify a proof
    ///
    /// Verifies that a proof correctly demonstrates the presence of a specific value
    /// at a specific index in the committed vector.
    ///
    /// # Arguments
    /// * `proof` - The proof to verify
    /// * `commitment` - The commitment to the vector
    /// * `value` - The claimed value at the index
    /// * `index` - The claimed index
    /// * `params` - Public parameters from keygen
    ///
    /// # Returns
    /// true if the proof is valid, false otherwise
    fn verify(
        proof: &Self::Proof,
        commitment: &Self::Commitment,
        value: &Self::Element,
        index: usize,
        params: &Self::PublicParams,
    ) -> bool;
}
