use crate::error::Error;
use crate::message::Message;

use async_trait::async_trait;
use ockam_core::{Address, Result, Worker};
use tokio::sync::mpsc::Sender;

#[derive(Clone)]
pub struct Node {
    sender: Sender<Message>,
}

impl Node {
    pub fn new(sender: Sender<Message>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl ockam_core::Node for Node {
    async fn stop(&self) -> Result<()> {
        match self.sender.send(Message::stop()).await {
            Ok(()) => Ok(()),
            Err(_e) => Err(Error::FailedStopNode.into()),
        }
    }

    /// Create and start the handler at [`Address`].
    async fn start_worker(&self, address: Address, worker: impl Worker) -> Result<()> {
        let start_worker_message = Message::start_worker(address, Box::new(worker));
        match self.sender.send(start_worker_message).await {
            Ok(()) => Ok(()),
            Err(_e) => Err(Error::FailedStartWorker.into()),
        }
    }
}
