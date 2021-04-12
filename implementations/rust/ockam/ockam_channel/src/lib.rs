//! Secure channel types and traits of the Ockam library.
//!
//! This crate contains the secure channel types of the Ockam library and is intended
//! for use by other crates that provide features and add-ons to the main
//! Ockam library.
//!
//! The main Ockam crate re-exports types defined in this crate.
#![deny(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    warnings
)]
mod error;
mod key_exchange;
mod secure_channel;
mod secure_channel_listener;

pub use error::*;
pub use secure_channel::*;
pub use secure_channel_listener::*;

#[cfg(test)]
mod tests {
    use crate::SecureChannel;
    use ockam_core::Route;

    #[test]
    fn simplest_channel() {
        let (mut ctx, mut executor) = ockam_node::start_node();
        executor
            .execute(async move {
                SecureChannel::create_listener(&ctx, "secure_channel_listener".to_string()).await?;
                SecureChannel::create(&mut ctx, Route::new().append("secure_channel_listener"))
                    .await?;
                ctx.stop().await
            })
            .unwrap();
    }
}