/// A verifiable anonymous credential (VAC), consists of 
///     1. Witness of membershipt to the Issuer's valid set 
///        of credentials 
///     2. An attribute vector that conforms to some specified 
///        schema 
/// 
/// A credential comes equipped with the following algorithms
///     1. ProveValid 
///     2. Discose  
///     3. ProveClaim 
///
/// ProveValid and ProveClaim both require access to a proof system. 
/// For now, it is enough to instantiate credentials with a general 
/// purpose proof system. In this case, relations are mapped to 
/// circuits. 

use serde::{Serialize, Deserialize};

/// Represents the possible types of values an attribute can hold
///
/// Attributes are the atomic units of a credential system. Issuers 
/// and Holders collaboritively choose attributes regarding subjects 
/// that Issuers then attest to. During credential presentations, 
/// Holders demonstrate that these attributes satisfy the policies 
/// specified by Verifiers. 
///
/// We should write a Hashable trait that is implemented by Attribute 
/// In every context, attributes should be hashed then either commited 
/// or signed directly. 
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AttributeValue {

    /// Signed 16-bit integer
    Integer(i16),
    
    /// Unsigned 16-bit integer
    UnsignedInteger(u16),
    
    /// Owned string
    String(String),
}

/// A credential containing a vector of attributes
///
/// Here we have a credential as a struct. But, in fact 
/// we should have different credentials with uniform 
/// interfaces. However, we require that credentials  
/// are implemented with (binding) vector commitments. 
/// 
/// This means that the credential is generic over: 
///     1. Vector commitment 
///     2. Proving backend
/// 
/// Not sure yet how to specify the proving backend. For now, 
/// we should ignore it. But we'll need to come back to it 
/// when we have better design considerations. 
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    attributes: Vec<AttributeValue>,
}

/// One question here is how we want the interface for a credential 
/// to look. When creating a new credential, we might want it to be 
/// like: 
///
/// let merkle_cred = Credential<MVC>::new(attributes) = ... 
/// This takes place on the Issuer side. The credential then gets 
/// distributed to the holder. In this case, the credential is 
/// generic over vector commitment schemes. The implementation here 
/// then generically implements its algorithms like Disclose and 
/// ProveValid over the vector commitment. 
///
/// The credential could in the future also be generic over proving 
/// backends. 
impl Credential {
    /// Create a new credential with the given attributes
    pub fn new(attributes: Vec<AttributeValue>) -> Self {
        Credential { attributes }
    }

    /// Get an attribute by index
    pub fn get(&self, index: usize) -> Option<&AttributeValue> {
        self.attributes.get(index)
    }

    /// Get the number of attributes in the credential
    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    /// Check if the credential has no attributes
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// Serialize each attribute to a vector of byte vectors using bincode
    ///
    /// Returns a Vec<Vec<u8>> where each inner Vec<u8> is the deterministic
    /// binary serialization of one attribute.
    pub fn to_byte_vector(&self) -> Result<Vec<Vec<u8>>, bincode::Error> {
        self.attributes
            .iter()
            .map(|attr| bincode::serialize(attr))
            .collect()
    }
}
