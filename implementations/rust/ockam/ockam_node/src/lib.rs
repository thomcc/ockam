//! ockam_node - Ockam Node API
#![deny(
    missing_docs,
    dead_code,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications
)]

#[macro_use]
extern crate tracing;

mod context;
mod error;
mod executor;
mod mailbox;
mod messages;
mod node;
mod parser;
mod relay;
mod router;

pub use context::*;
pub use executor::*;
pub use mailbox::*;
pub use messages::*;
pub use node::{start_node, NullWorker};
use ockam_core::{Address, Message, Result};
use std::future::Future;
use tokio::{runtime::Runtime, task};

/// Execute a future without blocking the executor
///
/// This is a wrapper around two simple tokio functions to allow
/// ockam_node to wait for a task to be completed in a non-async
/// environment.
///
/// This function is not meant to be part of the ockam public API, but
/// as an implementation utility for other ockam utilities that use
/// tokio.
#[doc(hidden)]
pub fn block_future<'r, F>(rt: &'r Runtime, f: F) -> <F as Future>::Output
where
    F: Future + Send,
    F::Output: Send,
{
    task::block_in_place(move || {
        let local = task::LocalSet::new();
        local.block_on(rt, f)
    })
}

#[doc(hidden)]
pub fn spawn<F: 'static>(f: F)
where
    F: Future + Send,
    F::Output: Send,
{
    task::spawn(f);
}

/// A representation of a worker on the 'client side'
pub struct Stub {
    /// Messaging context
    pub ctx: Context,
    /// Worker address
    pub address: Address,
}

impl Clone for Stub {
    fn clone(&self) -> Self {
        block_future(&self.ctx.runtime(), async move {
            Stub {
                ctx: self
                    .ctx
                    .new_context(Address::random(0))
                    .await
                    .expect("new_context failed"),
                address: self.address.clone(),
            }
        })
    }
}

/// Messages that stubs can send and receive
pub trait StubMessage: Message + Send + 'static {}

impl<M> StubMessage for M where M: Message + Send + 'static {}

impl Stub {
    /// Create a new stub for the worker at Address, using Context
    pub fn new(ctx: Context, address: Address) -> Self {
        Stub { ctx, address }
    }

    /// Asynchronously cast a message to a worker
    pub async fn async_cast<M: StubMessage>(&self, msg: M) -> Result<()> {
        self.ctx.send(self.address.clone(), msg).await
    }

    /// Cast a message to a worker
    pub fn cast<M: StubMessage>(&self, msg: M) -> Result<()> {
        block_future(
            &self.ctx.runtime(),
            async move { self.async_cast(msg).await },
        )
    }

    /// Asynchronously call a worker method and expect a response message
    pub async fn async_call<I: StubMessage, O: StubMessage>(&self, msg: I) -> Result<O> {
        let mut ctx = self
            .ctx
            .new_context(Address::random(0))
            .await
            .expect("new_context failed");
        ctx.send(self.address.clone(), msg).await?;
        let msg = ctx.receive::<O>().await?;
        Ok(msg.take().body())
    }

    /// Call a worker method and expect a response message
    pub fn call<I: StubMessage, O: StubMessage>(&self, msg: I) -> Result<O> {
        block_future(
            &self.ctx.runtime(),
            async move { self.async_call(msg).await },
        )
    }
}
