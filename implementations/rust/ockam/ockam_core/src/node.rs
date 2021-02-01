use crate::{Address, Result, Worker};
use async_trait::async_trait;

#[async_trait]
pub trait Node {
    async fn stop(&self) -> Result<()>;
    async fn start_worker(&self, _address: Address, _worker: impl Worker) -> Result<()>;
}
