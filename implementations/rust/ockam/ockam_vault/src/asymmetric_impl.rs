use crate::{
    AsymmetricVault, Buffer, PublicKey, Secret, SecretAttributes, SecretPersistence, SecretType,
    SecretVault, SoftwareVault, VaultEntry, VaultError, CURVE25519_PUBLIC_LENGTH,
    CURVE25519_SECRET_LENGTH,
};
use arrayref::array_ref;

impl SoftwareVault {
    fn ecdh_internal(
        vault_entry: &VaultEntry,
        peer_public_key: &PublicKey,
    ) -> ockam_core::Result<Buffer<u8>> {
        let key = vault_entry.key();
        match vault_entry.key_attributes().stype() {
            SecretType::Curve25519 => {
                if peer_public_key.as_ref().len() != CURVE25519_PUBLIC_LENGTH
                    || key.as_ref().len() != CURVE25519_SECRET_LENGTH
                {
                    return Err(VaultError::UnknownEcdhKeyType.into());
                }

                let sk = x25519_dalek::StaticSecret::from(*array_ref!(
                    key.as_ref(),
                    0,
                    CURVE25519_SECRET_LENGTH
                ));
                let pk_t = x25519_dalek::PublicKey::from(*array_ref!(
                    peer_public_key.as_ref(),
                    0,
                    CURVE25519_PUBLIC_LENGTH
                ));
                let secret = sk.diffie_hellman(&pk_t);
                Ok(secret.as_bytes().to_vec())
            }
            SecretType::P256 | SecretType::Buffer | SecretType::Aes | SecretType::Bls => {
                Err(VaultError::UnknownEcdhKeyType.into())
            }
        }
    }
}

impl AsymmetricVault for SoftwareVault {
    fn ec_diffie_hellman(
        &mut self,
        context: &Secret,
        peer_public_key: &PublicKey,
    ) -> ockam_core::Result<Secret> {
        let entry = self.get_entry(context)?;

        let dh = Self::ecdh_internal(entry, peer_public_key)?;

        let attributes =
            SecretAttributes::new(SecretType::Buffer, SecretPersistence::Ephemeral, dh.len());
        self.secret_import(&dh, attributes)
    }
}

// TODO JDS
/*#[cfg(test)]
mod tests {
    use crate::SoftwareVault;
    use ockam_vault_test_attribute::*;

    fn new_vault() -> SoftwareVault {
        SoftwareVault::default()
    }

    #[vault_test]
    fn ec_diffie_hellman_curve25519() {}
}
*/
