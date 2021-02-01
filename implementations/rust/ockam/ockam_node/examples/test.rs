use ockam_core::{Context, Node, Result, Worker};
use ockam_node::Context as NodeContext;

struct Printer;
impl Worker for Printer {
    type Context = NodeContext;

    fn initialize(&mut self, _context: &mut Self::Context) -> Result<()> {
        println!("hello");
        Ok(())
    }
}

fn main() {
    let (context, mut executor) = ockam_node::node();
    executor
        .execute(async move {
            let node = context.node();
            node.start_worker(String::from("a"), Printer {})
                .await
                .unwrap();

            node.stop().await.unwrap();
        })
        .unwrap()
}
