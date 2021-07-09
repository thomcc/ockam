use crate::{
    AsDataSlice, Data, HashBytes, KeyId, PublicKey, Rng, Secret, SecretAttributes, SecretKey,
    SignatureBytes, SmallBuffer,
};
use ockam_core::Result;
use zeroize::Zeroize;

/// TODO JDS The Vault trait description
pub trait VaultTrait: Zeroize + Send + 'static {
    /// Compute Elliptic-Curve Diffie-Hellman using this secret key
    /// and the specified uncompressed public key
    fn ecdh(&mut self, context: &Secret, peer_public_key: &PublicKey) -> Result<Secret>;

    /// Compute the SHA-256 digest given input `data`
    fn sha256<D: AsDataSlice>(&mut self, data: D) -> Result<HashBytes>;

    /// Derive multiple output [`Secret`]s with given attributes using the HKDF-SHA256 using
    /// specified salt, input key material and data.
    fn hkdf_sha256<D: AsDataSlice>(
        &mut self,
        salt: &Secret,
        data: D,
        input_key_material: Option<&Secret>,
        output_attributes: SmallBuffer<SecretAttributes>,
    ) -> Result<SmallBuffer<Secret>>;

    /// Return [`Secret`] for given key id
    fn load_secret_by_id<S: ToString>(&mut self, key_id: S) -> Result<Secret>;

    /// Return KeyId for given public key
    fn find_id_for_key(&mut self, public_key: &PublicKey) -> Result<KeyId>;

    /// Generate fresh secret with given attributes
    fn generate_secret(&mut self, attributes: SecretAttributes) -> Result<Secret>;

    /// Import a secret with given attributes from binary form into the vault
    fn import_secret<D: AsDataSlice>(
        &mut self,
        secret: D,
        attributes: SecretAttributes,
    ) -> Result<Secret>;

    /// Export a secret key to the binary form represented as [`SecretKey`]
    fn export_secret(&mut self, context: &Secret) -> Result<SecretKey>;

    /// Get the attributes for a secret
    fn load_secret_attributes(&mut self, context: &Secret) -> Result<SecretAttributes>;

    /// Return the associated public key given the secret key
    fn load_public_key_for_secret(&mut self, context: &Secret) -> Result<PublicKey>;

    /// Remove a secret from the vault
    fn destroy_secret(&mut self, context: Secret) -> Result<()>;

    /// Generate a signature  for given data using given secret key
    fn sign<D: AsDataSlice>(&mut self, secret_key: &Secret, data: D) -> Result<SignatureBytes>;

    /// Encrypt a payload using AES-GCM
    fn encrypt_aead_aes_gcm<P: AsDataSlice, N: AsDataSlice, A: AsDataSlice>(
        &mut self,
        context: &Secret,
        plaintext: P,
        nonce: N,
        aad: A,
    ) -> Result<Data>;

    /// Decrypt a payload using AES-GCM
    fn decrypt_aead_aes_gcm<C: AsDataSlice, N: AsDataSlice, A: AsDataSlice>(
        &mut self,
        context: &Secret,
        cipher_text: C,
        nonce: N,
        aad: A,
    ) -> Result<Data>;

    /// Verify a signature for given data using given public key
    fn verify<D: AsDataSlice>(
        &mut self,
        signature: &SignatureBytes,
        public_key: &PublicKey,
        data: D,
    ) -> Result<bool>;

    /// CSPRNG
    fn rng(&self) -> Rng {
        Rng::new()
    }
}
