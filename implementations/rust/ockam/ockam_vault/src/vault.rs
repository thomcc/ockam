use crate::{
    AsDataSlice, Data, HashBytes, KeyId, PublicKey, Secret, SecretAttributes, SecretKey,
    SignatureBytes, SmallBuffer, SoftwareVaultBuilder, VaultRequestMessage, VaultResponseMessage,
    VaultSyncCoreError, VaultTrait,
};
use ockam_core::{Address, Result};
use ockam_node::{block_future, Context, Stub};
use tracing::debug;
use zeroize::Zeroize;
use VaultRequestMessage::*;
use VaultResponseMessage as Res;

/// TODO JDS Vault description
pub struct Vault(Stub);

impl Vault {
    /// Start another Vault at the same address.
    pub fn start_another(&self) -> Result<Self> {
        let vault_worker_address = self.0.address.clone();
        let clone = Vault::create_with_worker(&self.0.ctx, &vault_worker_address)?;

        Ok(clone)
    }

    /// Call wrapper for VaultRequestMessage and VaultResponseMessage
    pub fn call(&self, msg: VaultRequestMessage) -> Result<VaultResponseMessage> {
        self.0.call(msg)
    }
}

impl Clone for Vault {
    fn clone(&self) -> Self {
        self.start_another().unwrap()
    }
}

impl Zeroize for Vault {
    fn zeroize(&mut self) {}
}

impl Vault {
    /// Create and start a new Vault using Worker.
    pub fn create_with_worker(ctx: &Context, vault: &Address) -> Result<Self> {
        debug!("Starting Vault at {}", &vault);

        let ctx = block_future(&ctx.runtime(), async move {
            ctx.new_context(vault.clone()).await
        })?;

        Ok(Self(Stub::new(ctx, vault.clone())))
    }

    /// Start a Vault.
    pub fn create_software<T: VaultTrait>(ctx: &Context, vault: T) -> Result<Self> {
        let vault_address = SoftwareVaultBuilder::create_with_inner(ctx, vault)?;

        Self::create_with_worker(ctx, &vault_address)
    }

    /// Return the Vault worker address
    pub fn address(&self) -> Address {
        self.0.address.clone()
    }
}

fn err<O>() -> Result<O> {
    Err(VaultSyncCoreError::InvalidResponseType.into())
}

impl VaultTrait for Vault {
    fn ecdh(&mut self, context: &Secret, peer_public_key: &PublicKey) -> Result<Secret> {
        if let Res::Ecdh(secret) = self.call(Ecdh {
            context: context.clone(),
            peer_public_key: peer_public_key.clone(),
        })? {
            Ok(secret)
        } else {
            err()
        }
    }

    fn sha256<D: AsDataSlice>(&mut self, data: D) -> Result<HashBytes> {
        if let Res::Sha256(hash) = self.call(Sha256(data.as_ref().into()))? {
            Ok(hash)
        } else {
            err()
        }
    }

    fn hkdf_sha256<D: AsDataSlice>(
        &mut self,
        salt: &Secret,
        info: D,
        input_key_material: Option<&Secret>,
        output_attributes: SmallBuffer<SecretAttributes>,
    ) -> Result<SmallBuffer<Secret>> {
        if let Res::HkdfSha256(secret) = self.call(HkdfSha256 {
            salt: salt.clone(),
            data: info.as_ref().into(),
            ikm: input_key_material.cloned(),
            output_attributes,
        })? {
            Ok(secret)
        } else {
            err()
        }
    }

    fn load_secret_by_id<S: ToString>(&mut self, key_id: S) -> Result<Secret> {
        if let Res::LoadSecretById(secret) = self.call(LoadSecretById(key_id.to_string()))? {
            Ok(secret)
        } else {
            err()
        }
    }

    fn find_id_for_key(&mut self, public_key: &PublicKey) -> Result<KeyId> {
        if let Res::FindIdForKey(key_id) = self.call(FindIdForKey(public_key.clone()))? {
            Ok(key_id)
        } else {
            err()
        }
    }

    fn generate_secret(&mut self, attributes: SecretAttributes) -> Result<Secret> {
        if let Res::GenerateSecret(secret) = self.call(GenerateSecret(attributes))? {
            Ok(secret)
        } else {
            err()
        }
    }

    fn import_secret<D: AsDataSlice>(
        &mut self,
        secret: D,
        attributes: SecretAttributes,
    ) -> Result<Secret> {
        if let Res::ImportSecret(imported_secret) = self.call(ImportSecret {
            secret: secret.as_ref().into(),
            attributes,
        })? {
            Ok(imported_secret)
        } else {
            err()
        }
    }

    fn export_secret(&mut self, context: &Secret) -> Result<SecretKey> {
        if let Res::ExportSecret(secret_key) = self.call(ExportSecret(context.clone()))? {
            Ok(secret_key)
        } else {
            err()
        }
    }

    fn load_secret_attributes(&mut self, context: &Secret) -> Result<SecretAttributes> {
        if let Res::LoadSecretAttributes(secret_attributes) =
            self.call(LoadSecretAttributes(context.clone()))?
        {
            Ok(secret_attributes)
        } else {
            err()
        }
    }

    fn load_public_key_for_secret(&mut self, context: &Secret) -> Result<PublicKey> {
        if let Res::LoadPublicKeyForSecret(public_key) =
            self.call(LoadPublicKeyForSecret(context.clone()))?
        {
            Ok(public_key)
        } else {
            err()
        }
    }

    fn destroy_secret(&mut self, context: Secret) -> Result<()> {
        if let Res::DestroySecret = self.call(DestroySecret(context.clone()))? {
            Ok(())
        } else {
            err()
        }
    }

    fn sign<D: AsDataSlice>(&mut self, secret_key: &Secret, data: D) -> Result<SignatureBytes> {
        if let Res::Sign(signature) = self.call(Sign {
            secret_key: secret_key.clone(),
            data: data.as_ref().into(),
        })? {
            Ok(signature)
        } else {
            err()
        }
    }

    fn encrypt_aead_aes_gcm<P: AsDataSlice, N: AsDataSlice, A: AsDataSlice>(
        &mut self,
        context: &Secret,
        plaintext: P,
        nonce: N,
        aad: A,
    ) -> Result<Data> {
        if let Res::EncryptAeadAesGcm(data) = self.call(EncryptAeadAesGcm {
            context: context.clone(),
            plaintext: plaintext.as_ref().into(),
            nonce: nonce.as_ref().into(),
            aad: aad.as_ref().into(),
        })? {
            Ok(data)
        } else {
            err()
        }
    }

    fn decrypt_aead_aes_gcm<C: AsDataSlice, N: AsDataSlice, A: AsDataSlice>(
        &mut self,
        context: &Secret,
        cipher_text: C,
        nonce: N,
        aad: A,
    ) -> Result<Data> {
        if let Res::DecryptAeadAesGcm(data) = self.call(DecryptAeadAesGcm {
            context: context.clone(),
            cipher_text: cipher_text.as_ref().into(),
            nonce: nonce.as_ref().into(),
            aad: aad.as_ref().into(),
        })? {
            Ok(data)
        } else {
            err()
        }
    }

    fn verify<D: AsDataSlice>(
        &mut self,
        signature: &SignatureBytes,
        public_key: &PublicKey,
        data: D,
    ) -> Result<bool> {
        if let Res::Verify(verified) = self.call(Verify {
            signature: *signature,
            public_key: public_key.clone(),
            data: data.as_ref().into(),
        })? {
            Ok(verified)
        } else {
            err()
        }
    }
}
