use rand::prelude::ThreadRng;
use rand::thread_rng;

/// Random Number Generator
pub struct Rng(ThreadRng);

impl Rng {
    /// Create a new CSPRNG
    pub fn new() -> Self {
        Rng(thread_rng())
    }
}
