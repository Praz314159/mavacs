/// Merkle Errors 


/// TODO: implement display trait 
#[derive(Debug, PartialEq, Eq)]
pub enum TreeIndexError {
    RootHasNoParent,
    IndexOutOfBounds,
    LeafHasNoChildren,
}


