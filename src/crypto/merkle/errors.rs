/// Merkle Errors

use std::fmt;
use std::error::Error;

#[derive(Debug, PartialEq, Eq)]
pub enum TreeIndexError {
    RootHasNoParent,
    IndexOutOfBounds,
    LeafHasNoChildren,
}

impl fmt::Display for TreeIndexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TreeIndexError::RootHasNoParent =>
                write!(f, "Root node has no parent"),
            TreeIndexError::IndexOutOfBounds =>
                write!(f, "Index out of bounds"),
            TreeIndexError::LeafHasNoChildren =>
                write!(f, "Leaf node has no children"),
        }
    }
}

impl Error for TreeIndexError {}


