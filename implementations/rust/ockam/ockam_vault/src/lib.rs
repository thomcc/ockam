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

pub use error::*;
pub use error::*;
pub use software::vault_builder::*;
pub use software::xeddsa::*;
pub use software::*;
pub use traits::*;
pub use types::*;
pub use vault::*;
pub use worker::*;

mod error;
mod request;
mod response;
mod traits;
mod types;
mod vault;
mod worker;

// Software Vault
mod software;
/// Create drop implementation with zeroize call
#[macro_export]
macro_rules! zdrop_impl {
    ($name:ident) => {
        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }
    };
}
