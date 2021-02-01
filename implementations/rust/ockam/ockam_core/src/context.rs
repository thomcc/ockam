use super::Address;
use async_trait::async_trait;

#[async_trait]
pub trait Context {
    type Node;

    fn address(&self) -> Address;
    fn node(&self) -> Self::Node;
}
