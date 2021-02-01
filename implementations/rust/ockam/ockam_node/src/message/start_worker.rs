use crate::executor::Executor;
use ockam_core::Address;
use std::any::Any;

/// Implementation of the StartWorker [`Message`]. Starts and registers a new Worker.
pub struct StartWorker {
    pub address: Address,
    pub worker: Box<dyn Any + Send>,
}

impl StartWorker {
    pub fn handle(self, executor: &mut Executor) -> bool {
        executor.register(self.address, self.worker).unwrap();
        false
    }
}
