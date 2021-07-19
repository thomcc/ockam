// This node creates a worker, sends it a message, and receives a reply.

use ockam::{Context, Result, Routed};
use core::pin::Pin;
use core::future::Future;

/// This looks awful, but compiles and proves the point. This would be result
/// from the expansion of the `#[ockam::worker]` macro when applied to a
/// function.
///
/// E.g, the user would actually write something like:
///
/// ```ignore
/// #[ockam::worker]
/// async fn echoer(ctx: &mut Context, msg: Routed<String>) -> Result<()> {
///     ctx.send(msg.return_route(), msg.body()).await
/// }
/// ```
///
/// Which would be expanded into this:
fn echoer<'ctx>(ctx: &'ctx mut Context, msg: Routed<String>) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'ctx>> {
    Box::pin(async move {
        ctx.send(msg.return_route(), msg.body()).await
    })
}

#[ockam::node]
async fn main(mut ctx: Context) -> Result<()> {
    // Start a worker, of type Echoer, at address "echoer"

    ctx.start_function_worker("echoer", echoer).await?;

    // Send a message to the worker at address "echoer".
    ctx.send("echoer", "Hello Ockam!".to_string()).await?;

    // Wait to receive a reply and print it.
    let reply = ctx.receive::<String>().await?;
    println!("App Received: {}", reply); // should print "Hello Ockam!"

    // Stop all workers, stop the node, cleanup and return.
    ctx.stop().await
}
