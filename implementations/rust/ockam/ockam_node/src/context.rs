use crate::node::Node;
use ockam_core::Address;

#[derive(Clone)]
pub struct Context {
    address: Address,
    node: Node,
}

impl Context {
    pub fn new(node: Node, address: Address) -> Self {
        Self { address, node }
    }
}

impl ockam_core::Context for Context {
    type Node = Node;

    fn address(&self) -> Address {
        self.address.clone()
    }

    fn node(&self) -> Self::Node {
        self.node.clone()
    }
}
