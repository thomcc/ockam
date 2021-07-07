use async_trait::async_trait;
use ockam_core::{Address, Result, ResultMessage, Routed, Worker};
use ockam_node::Context;
use rand::random;
use zeroize::Zeroize;

pub(crate) use crate::request::*;
pub(crate) use crate::response::*;
use crate::VaultTrait;
use VaultRequestMessage::*;
use VaultResponseMessage as Res;

/// A Worker that exposes a Vault API.
#[derive(Zeroize)]
pub struct VaultWorker<V>
where
    V: VaultTrait,
{
    inner: V,
}

impl<V> VaultWorker<V>
where
    V: VaultTrait,
{
    /// Create a new VaultWorker.
    fn new(inner: V) -> Self {
        Self { inner }
    }

    /// Start a VaultWorker.
    pub async fn create_with_inner(ctx: &Context, inner: V) -> Result<Address> {
        let address: Address = random();
        ctx.start_worker(address.clone(), Self::new(inner)).await?;
        Ok(address)
    }

    fn handle_request(&mut self, msg: <Self as Worker>::Message) -> Result<VaultResponseMessage> {
        Ok(match msg {
            Ecdh {
                context,
                peer_public_key,
            } => Res::Ecdh(self.inner.ecdh(&context, &peer_public_key)?),
            Sha256(data) => Res::Sha256(self.inner.sha256(&data)?),
            HkdfSha256 {
                salt,
                data: info,
                ikm,
                output_attributes,
            } => Res::HkdfSha256(self.inner.hkdf_sha256(
                &salt,
                &info,
                ikm.as_ref(),
                output_attributes,
            )?),
            LoadSecretById(key_id) => Res::LoadSecretById(self.inner.load_secret_by_id(&key_id)?),
            FindIdForKey(public_key) => Res::FindIdForKey(self.inner.find_id_for_key(&public_key)?),
            GenerateSecret(attributes) => {
                Res::GenerateSecret(self.inner.generate_secret(attributes)?)
            }
            ImportSecret { secret, attributes } => {
                Res::ImportSecret(self.inner.import_secret(&secret, attributes)?)
            }
            ExportSecret(secret) => Res::ExportSecret(self.inner.export_secret(&secret)?),
            LoadSecretAttributes(secret) => {
                Res::LoadSecretAttributes(self.inner.load_secret_attributes(&secret)?)
            }
            LoadPublicKeyForSecret(secret) => {
                Res::LoadPublicKeyForSecret(self.inner.load_public_key_for_secret(&secret)?)
            }
            DestroySecret(secret) => {
                self.inner.destroy_secret(secret)?;
                Res::DestroySecret
            }
            Sign { secret_key, data } => Res::Sign(self.inner.sign(&secret_key, &data)?),
            EncryptAeadAesGcm {
                context,
                plaintext,
                nonce,
                aad,
            } => Res::EncryptAeadAesGcm(
                self.inner
                    .encrypt_aead_aes_gcm(&context, &plaintext, &nonce, &aad)?,
            ),
            DecryptAeadAesGcm {
                context,
                cipher_text,
                nonce,
                aad,
            } => Res::DecryptAeadAesGcm(self.inner.decrypt_aead_aes_gcm(
                &context,
                &cipher_text,
                &nonce,
                &aad,
            )?),
            Verify {
                signature,
                public_key,
                data,
            } => {
                let verify_call = self.inner.verify(&signature, &public_key, &data);
                if verify_call.is_err() {
                    Res::Verify(false)
                } else {
                    let verified = verify_call.unwrap();
                    Res::Verify(verified)
                }
            }
        })
    }
}

#[async_trait]
impl<V> Worker for VaultWorker<V>
where
    V: VaultTrait + 'static,
{
    type Message = VaultRequestMessage;
    type Context = Context;

    async fn handle_message(
        &mut self,
        ctx: &mut Self::Context,
        msg: Routed<Self::Message>,
    ) -> Result<()> {
        let return_route = msg.return_route();
        let response = self.handle_request(msg.body());

        let response = ResultMessage::new(response);

        ctx.send(return_route, response).await?;

        Ok(())
    }
}
