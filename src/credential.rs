use serde::{Serialize, Deserialize};

/// Represents the possible types of values an attribute can hold
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    attributes: Vec<AttributeValue>,
}

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
