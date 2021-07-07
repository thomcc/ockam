use crate::{
    AsDataSlice, Data, KeyId, PublicKey, Secret, SecretAttributes, SecretKey, SignatureBytes,
    SmallBuffer, SoftwareVaultBuilder, VaultRequestMessage, VaultResponseMessage,
    VaultSyncCoreError, VaultTrait,
};
use ockam_core::{Address, Result, ResultMessage, Route};
use ockam_node::{block_future, Context};
use rand::random;
use tracing::debug;
use zeroize::Zeroize;

/// TODO JDS Vault
pub struct Vault {
    ctx: Context,
    vault_worker_address: Address,
}

impl Vault {
    pub(crate) async fn send_message(&self, m: VaultRequestMessage) -> Result<()> {
        self.ctx
            .send(Route::new().append(self.vault_worker_address.clone()), m)
            .await
    }

    pub(crate) async fn receive_message(&mut self) -> Result<VaultResponseMessage> {
        self.ctx
            .receive::<ResultMessage<VaultResponseMessage>>()
            .await?
            .take()
            .body()
            .into()
    }
}

impl Clone for Vault {
    fn clone(&self) -> Self {
        self.start_another().unwrap()
    }
}

impl Vault {
    /// Start another Vault at the same address.
    pub fn start_another(&self) -> Result<Self> {
        let vault_worker_address = self.vault_worker_address.clone();

        let clone = Vault::create_with_worker(&self.ctx, &vault_worker_address)?;

        Ok(clone)
    }
}

impl Zeroize for Vault {
    fn zeroize(&mut self) {}
}

impl Vault {
    /// Create and start a new Vault using Worker.
    pub fn create_with_worker(ctx: &Context, vault: &Address) -> Result<Self> {
        let address: Address = random();

        debug!("Starting VaultSync at {}", &address);

        let ctx = block_future(
            &ctx.runtime(),
            async move { ctx.new_context(address).await },
        )?;

        Ok(Self {
            ctx,
            vault_worker_address: vault.clone(),
        })
    }

    /// Start a Vault.
    pub fn create_software<T: VaultTrait>(ctx: &Context, vault: T) -> Result<Self> {
        let vault_address = SoftwareVaultBuilder::create_with_inner(ctx, vault)?;

        Self::create_with_worker(ctx, &vault_address)
    }

    /// Return the Vault worker address
    pub fn address(&self) -> Address {
        self.vault_worker_address.clone()
    }
}

impl VaultTrait for Vault {
    fn ecdh(&mut self, context: &Secret, peer_public_key: &PublicKey) -> Result<Secret> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::Ecdh {
                context: context.clone(),
                peer_public_key: peer_public_key.clone(),
            })
            .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::Ecdh(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn sha256<D: AsDataSlice>(&mut self, data: D) -> Result<[u8; 32]> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::Sha256(data.as_ref().into()))
                .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::Sha256(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn hkdf_sha256<D: AsDataSlice>(
        &mut self,
        salt: &Secret,
        info: D,
        input_key_material: Option<&Secret>,
        output_attributes: SmallBuffer<SecretAttributes>,
    ) -> Result<SmallBuffer<Secret>> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::HkdfSha256 {
                salt: salt.clone(),
                data: info.as_ref().into(),
                ikm: input_key_material.cloned(),
                output_attributes,
            })
            .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::HkdfSha256(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn load_secret_by_id(&mut self, key_id: &str) -> Result<Secret> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::LoadSecretById(key_id.to_string()))
                .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::LoadSecretById(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn find_id_for_key(&mut self, public_key: &PublicKey) -> Result<KeyId> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::FindIdForKey(public_key.clone()))
                .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::FindIdForKey(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn generate_secret(&mut self, attributes: SecretAttributes) -> Result<Secret> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::GenerateSecret(attributes))
                .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::GenerateSecret(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn import_secret<D: AsDataSlice>(
        &mut self,
        secret: D,
        attributes: SecretAttributes,
    ) -> Result<Secret> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::ImportSecret {
                secret: secret.as_ref().into(),
                attributes,
            })
            .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::ImportSecret(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn export_secret(&mut self, context: &Secret) -> Result<SecretKey> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::ExportSecret(context.clone()))
                .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::ExportSecret(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn load_secret_attributes(&mut self, context: &Secret) -> Result<SecretAttributes> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::LoadSecretAttributes(context.clone()))
                .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::LoadSecretAttributes(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn load_public_key_for_secret(&mut self, context: &Secret) -> Result<PublicKey> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::LoadPublicKeyForSecret(context.clone()))
                .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::LoadPublicKeyForSecret(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn destroy_secret(&mut self, context: Secret) -> Result<()> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::DestroySecret(context.clone()))
                .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::DestroySecret = resp {
                Ok(())
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn sign<D: AsDataSlice>(&mut self, secret_key: &Secret, data: D) -> Result<SignatureBytes> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::Sign {
                secret_key: secret_key.clone(),
                data: data.as_ref().into(),
            })
            .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::Sign(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn encrypt_aead_aes_gcm<P: AsDataSlice, N: AsDataSlice, A: AsDataSlice>(
        &mut self,
        context: &Secret,
        plaintext: P,
        nonce: N,
        aad: A,
    ) -> Result<Data> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::EncryptAeadAesGcm {
                context: context.clone(),
                plaintext: plaintext.as_ref().into(),
                nonce: nonce.as_ref().into(),
                aad: aad.as_ref().into(),
            })
            .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::EncryptAeadAesGcm(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn decrypt_aead_aes_gcm<C: AsDataSlice, N: AsDataSlice, A: AsDataSlice>(
        &mut self,
        context: &Secret,
        cipher_text: C,
        nonce: N,
        aad: A,
    ) -> Result<Data> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::DecryptAeadAesGcm {
                context: context.clone(),
                cipher_text: cipher_text.as_ref().into(),
                nonce: nonce.as_ref().into(),
                aad: aad.as_ref().into(),
            })
            .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::DecryptAeadAesGcm(s) = resp {
                Ok(s)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }

    fn verify<D: AsDataSlice>(
        &mut self,
        signature: &SignatureBytes,
        public_key: &PublicKey,
        data: D,
    ) -> Result<bool> {
        block_future(&self.ctx.runtime(), async move {
            self.send_message(VaultRequestMessage::Verify {
                signature: *signature,
                public_key: public_key.clone(),
                data: data.as_ref().into(),
            })
            .await?;

            let resp = self.receive_message().await?;

            if let VaultResponseMessage::Verify(verified) = resp {
                Ok(verified)
            } else {
                Err(VaultSyncCoreError::InvalidResponseType.into())
            }
        })
    }
}
