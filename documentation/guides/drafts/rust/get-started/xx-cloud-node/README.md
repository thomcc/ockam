Ockam hub guides:

10-routing-to-a-cloud-node:

Intro into hub nodes

Create your node here: link to hub node creation guide OR section about hub node creation

Use the URL in the following example:

10-routing-to-a-cloud-node.rs

API to use host input in `let cloud_node_tcp_address = "";`

Ockam hub: add "copy to clipboard" button to the hostnames


# Using Cloud nodes

## Ockam Hub

In order to connect devices to each other and to cloud services, Ockam system implements Cloud Nodes.
These nodes are provided by the Ockam Hub service: hub.ockam.network

Hub Nodes run persistent workers, which are called services. Services can be used for discovery, routing and
integration with various services used by the application.

This guide shows how to start a new Hub Node, connect an application and use services in there.

## Creating Hub Nodes

Navigate to http://hub.ockam.network

In order to create a node, you need to log in using your GitHub account:

**image here**

After that you can create a routing node:

**image here**

When the node status changes to `Running`, the node is ready to use.

**image here**

You can copy the node name from the nodes list and use in the following example.

## Example service usage

In this example we're going to use the `echo_service` on the Hub Node we created. This service behaviour is similar to the `echoer` workers we used before - it will reply for a message with the same payload.

### Application code

Create a new file at:

```
touch examples/10-routing-to-a-cloud-node.rs
```

Add the following code to this file:

```rust
// This node routes a message, to a worker on a cloud node, over the tcp transport.

use ockam::{route, Context, Result, TcpTransport, TCP};

use std::net::{SocketAddr, ToSocketAddrs};

#[ockam::node]
async fn main(mut ctx: Context) -> Result<()> {
    // Create a cloud node by going to https://hub.ockam.network

    let cloud_node_tcp_address = "<Your node host copied from hub.ockam.network>:4000";

    // Initialize the TCP Transport.
    let tcp = TcpTransport::create(&ctx).await?;

    // Create a TCP connection to your cloud node.
    tcp.connect(cloud_node_tcp_address).await?;

    // Send a message to the `echo_service` worker on your cloud node.
    ctx.send(
        // route to the echo_service worker on your cloud node
        route![(TCP, cloud_node_tcp_address), "echo_service"],
        // the message you want echo-ed back
        "Hello Ockam!".to_string(),
    )
    .await?;

    // Wait to receive the echo and print it.
    let msg = ctx.receive::<String>().await?;
    println!("App Received: '{}'", msg); // should print "Hello Ockam!"

    // Stop the node.
    ctx.stop().await
}

```

### Run

```
cargo run --example 10-routing-to-a-cloud-node
```

<div style="display: none; visibility: hidden;">
<hr><b>Next:</b> <a href="../11-discovery-using-cloud-node">11. Discovery using cloud node</a>
</div>

