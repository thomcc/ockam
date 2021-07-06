use crate::VaultMutex;
use crate::{PublicKey, Verifier};
use ockam_core::Result;

impl<V: Verifier> Verifier for VaultMutex<V> {
    fn verify(
        &mut self,
        signature: &[u8; 64],
        public_key: &PublicKey,
        data: &[u8],
    ) -> Result<bool> {
        self.0.lock().unwrap().verify(signature, public_key, data)
    }
}
