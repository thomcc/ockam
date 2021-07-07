//! Builder entry point for Vault
//!
use crate::{SoftwareVault, VaultTrait, VaultWorker};
use ockam_core::{Address, Result};
use ockam_node::{block_future, Context};

/// Vault allows to start Vault Worker.
pub struct SoftwareVaultBuilder {}

impl SoftwareVaultBuilder {
    /// Start a Vault with SoftwareVault implementation.
    pub fn create(ctx: &Context) -> Result<Address> {
        Self::create_with_inner(ctx, SoftwareVault::default())
    }
    /// Start a Vault Worker with given implementation.
    pub fn create_with_inner<V: VaultTrait + 'static>(ctx: &Context, inner: V) -> Result<Address> {
        let rt = ctx.runtime();
        block_future(&rt, async {
            VaultWorker::create_with_inner(ctx, inner).await
        })
    }
}
