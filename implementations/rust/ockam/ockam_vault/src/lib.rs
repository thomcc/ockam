//! Software implementation of ockam_vault_core traits.
//!
//! This crate contains one of the possible implementation of the vault traits
//! which you can use with Ockam library.

#![deny(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    warnings
)]

mod asymmetric_impl;
mod asymmetric_vault;
mod error;
mod hasher;
mod hasher_impl;
mod key_id_impl;
mod key_id_vault;
mod macros;
mod secret;
mod secret_impl;
mod secret_vault;
mod signer;
mod signer_impl;
mod software_vault;
mod symmetric_impl;
mod symmetric_vault;
mod types;
mod vault;
mod vault_mutex;
mod vault_sync;
mod vault_worker;
mod verifier;
mod verifier_impl;
mod xeddsa;

pub use asymmetric_impl::*;
pub use asymmetric_vault::*;
pub use error::*;
pub use error::*;
pub use hasher::*;
pub use hasher_impl::*;
pub use key_id_impl::*;
pub use key_id_vault::*;
pub use macros::*;
pub use secret::*;
pub use secret_impl::*;
pub use secret_vault::*;
pub use signer::*;
pub use signer_impl::*;
pub use software_vault::*;
pub use symmetric_impl::*;
pub use symmetric_vault::*;
pub use types::*;
pub use vault::*;
pub use vault_mutex::*;
pub use vault_sync::*;
pub use vault_worker::*;
pub use verifier::*;
pub use verifier_impl::*;
