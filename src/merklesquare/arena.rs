use crate::merklesquare::hash::Hash32;

pub type NodeId = u32;

/// Node stored in a compact arena. Internal nodes refer to children by index.
#[derive(Clone, Debug)]
pub enum Node {
    Leaf {
        hash: Hash32,
        /// position among leaves (0-based)
        pos: u32,
    },
    Internal {
        left: NodeId,
        right: NodeId,
        hash: Hash32,
        /// height of this node (leaf = 0)
        height: u32,
        /// shift = pos >> height (optional bookkeeping)
        shift: u32,
    },
}

impl Node {
    #[inline] pub fn hash(&self) -> Hash32 {
        match self {
            Node::Leaf { hash, .. } => *hash,
            Node::Internal { hash, .. } => *hash,
        }
    }
    #[inline] pub fn height(&self) -> u32 {
        match self {
            Node::Leaf { .. } => 0,
            Node::Internal { height, .. } => *height,
        }
    }
}

#[derive(Default)]
pub struct Arena {
    nodes: Vec<Node>,
}

impl Arena {
    pub fn new() -> Self { Self { nodes: Vec::new() } }

    #[inline] pub fn get(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }
    #[inline] pub fn push(&mut self, node: Node) -> NodeId {
        let id = self.nodes.len() as NodeId;
        self.nodes.push(node);
        id
    }
    #[inline] pub fn len(&self) -> usize { self.nodes.len() }
}
