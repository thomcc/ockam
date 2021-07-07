use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use arrayref::array_ref;
use ockam_core::hex::encode;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use signature_bbs_plus::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
use zeroize::Zeroize;

use crate::{
    AsDataSlice, Data, HashBytes, KeyId, PublicKey, Secret, SecretAttributes, SecretKey,
    SecretPersistence, SecretType, SignatureBytes, VaultEntry, VaultError, VaultTrait,
    XEddsaSigner, XEddsaVerifier, AES128_SECRET_LENGTH, AES256_SECRET_LENGTH,
    CURVE25519_PUBLIC_LENGTH, CURVE25519_SECRET_LENGTH,
};
use ockam_core::lib::convert::TryInto;
use ockam_core::lib::BTreeMap;

macro_rules! encrypt_op_impl {
    ($a:expr,$aad:expr,$nonce:expr,$text:expr,$type:ident,$op:ident) => {{
        let key = GenericArray::from_slice($a.as_ref());
        let cipher = $type::new(key);
        let nonce = GenericArray::from_slice($nonce.as_ref());
        let payload = Payload {
            aad: $aad.as_ref(),
            msg: $text.as_ref(),
        };
        let output = cipher.$op(nonce, payload).or_else(|_| {
            Err(Into::<ockam_core::Error>::into(
                VaultError::AeadAesGcmEncrypt,
            ))
        })?;
        Ok(output)
    }};
}

macro_rules! encrypt_impl {
    ($entry:expr, $aad:expr, $nonce: expr, $text:expr, $op:ident, $err:expr) => {{
        if $entry.key_attributes().stype() != SecretType::Aes {
            return Err($err.into());
        }
        match $entry.key_attributes().length() {
            AES128_SECRET_LENGTH => {
                encrypt_op_impl!($entry.key().as_ref(), $aad, $nonce, $text, Aes128Gcm, $op)
            }
            AES256_SECRET_LENGTH => {
                encrypt_op_impl!($entry.key().as_ref(), $aad, $nonce, $text, Aes256Gcm, $op)
            }
            _ => Err($err.into()),
        }
    }};
}

/// TODO JDS A software vault implementation
pub struct SoftwareVault {
    pub(crate) entries: BTreeMap<usize, VaultEntry>,
    pub(crate) next_id: usize,
}

impl Zeroize for SoftwareVault {
    fn zeroize(&mut self) {
        for (_, v) in self.entries.iter_mut() {
            v.zeroize();
        }
        self.entries.clear();
        self.next_id = 0;
    }
}

impl SoftwareVault {
    /// Create a new software vault
    pub fn new() -> Self {
        Self {
            entries: Default::default(),
            next_id: 0,
        }
    }
    pub(crate) fn get_entry(&self, context: &Secret) -> ockam_core::Result<&VaultEntry> {
        self.entries
            .get(&context.index())
            .ok_or_else(|| VaultError::EntryNotFound.into())
    }
}

impl Default for SoftwareVault {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareVault {
    fn ecdh_internal(
        vault_entry: &VaultEntry,
        peer_public_key: &PublicKey,
    ) -> ockam_core::Result<Data> {
        let key = vault_entry.key();
        match vault_entry.key_attributes().stype() {
            SecretType::Curve25519 => {
                // TODO JDS some kind of is_valid
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
impl VaultTrait for SoftwareVault {
    fn ecdh(
        &mut self,
        context: &Secret,
        peer_public_key: &PublicKey,
    ) -> ockam_core::Result<Secret> {
        let entry = self.get_entry(context)?;

        let dh = Self::ecdh_internal(entry, peer_public_key)?;

        let attributes =
            SecretAttributes::new(SecretType::Buffer, SecretPersistence::Ephemeral, dh.len());
        self.import_secret(&dh, attributes)
    }

    fn sha256<D: AsDataSlice>(&mut self, data: D) -> ockam_core::Result<HashBytes> {
        let digest = Sha256::digest(data.as_ref());
        Ok(*array_ref![digest, 0, 32])
    }

    /// Compute sha256.
    /// Salt and Ikm should be of Buffer type.
    /// Output secrets should be only of type Buffer or AES
    fn hkdf_sha256<D: AsDataSlice>(
        &mut self,
        salt: &Secret,
        info: D,
        ikm: Option<&Secret>,
        output_attributes: Vec<SecretAttributes>,
    ) -> ockam_core::Result<Vec<Secret>> {
        let ikm: ockam_core::Result<&[u8]> = match ikm {
            Some(ikm) => {
                let ikm = self.get_entry(ikm)?;
                if ikm.key_attributes().stype() == SecretType::Buffer {
                    Ok(ikm.key().as_ref())
                } else {
                    Err(VaultError::InvalidKeyType.into())
                }
            }
            None => Ok(&[0u8; 0]),
        };

        let ikm = ikm?;

        let salt = self.get_entry(salt)?;

        if salt.key_attributes().stype() != SecretType::Buffer {
            return Err(VaultError::InvalidKeyType.into());
        }

        // FIXME: Doesn't work for secrets with size more than 32 bytes
        let okm_len = output_attributes.len() * 32;

        let okm = {
            let mut okm = vec![0u8; okm_len];
            let prk = hkdf::Hkdf::<Sha256>::new(Some(salt.key().as_ref()), ikm);

            prk.expand(info.as_ref(), okm.as_mut_slice())
                .map_err(|_| Into::<ockam_core::Error>::into(VaultError::HkdfExpandError))?;
            okm
        };

        let mut secrets = Vec::<Secret>::new();
        let mut index = 0;

        for attributes in output_attributes {
            let length = attributes.length();
            if attributes.stype() == SecretType::Aes {
                if length != AES256_SECRET_LENGTH && length != AES128_SECRET_LENGTH {
                    return Err(VaultError::InvalidAesKeyLength.into());
                }
            } else if attributes.stype() != SecretType::Buffer {
                return Err(VaultError::InvalidHkdfOutputType.into());
            }
            let secret = &okm[index..index + length];
            let secret = self.import_secret(secret, attributes)?;

            secrets.push(secret);
            index += 32;
        }

        Ok(secrets)
    }

    fn load_secret_by_id(&mut self, key_id: &str) -> ockam_core::Result<Secret> {
        let index = self
            .entries
            .iter()
            .find(|(_, entry)| {
                if let Some(e_key_id) = entry.key_id() {
                    e_key_id == key_id
                } else {
                    false
                }
            })
            .ok_or_else(|| Into::<ockam_core::Error>::into(VaultError::SecretNotFound))?
            .0;

        Ok(Secret::new(*index))
    }

    fn find_id_for_key(&mut self, public_key: &PublicKey) -> ockam_core::Result<KeyId> {
        let key_id = self.sha256(public_key.as_ref())?;
        Ok(encode(key_id))
    }

    /// Generate fresh secret. Only Curve25519 and Buffer types are supported
    fn generate_secret(&mut self, attributes: SecretAttributes) -> ockam_core::Result<Secret> {
        let mut rng = thread_rng(); // TODO JDS
        let (key, key_id) = match attributes.stype() {
            SecretType::Curve25519 => {
                // FIXME
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                let sk = x25519_dalek::StaticSecret::from(bytes);
                let public = x25519_dalek::PublicKey::from(&sk);
                let private = SecretKey::new(sk.to_bytes().to_vec());
                let key_id = self.find_id_for_key(&PublicKey::new(public.as_bytes().to_vec()))?;

                (private, Some(key_id))
            }
            SecretType::Buffer => {
                if attributes.persistence() != SecretPersistence::Ephemeral {
                    return Err(VaultError::InvalidKeyType.into());
                };
                let mut key = vec![0u8; attributes.length()];
                rng.fill_bytes(key.as_mut_slice());
                (SecretKey::new(key), None)
            }
            SecretType::Aes => {
                if attributes.length() != AES256_SECRET_LENGTH
                    && attributes.length() != AES128_SECRET_LENGTH
                {
                    return Err(VaultError::InvalidAesKeyLength.into());
                };
                if attributes.persistence() != SecretPersistence::Ephemeral {
                    return Err(VaultError::InvalidKeyType.into());
                };
                let mut key = vec![0u8; attributes.length()];
                rng.fill_bytes(&mut key);
                (SecretKey::new(key), None)
            }
            SecretType::P256 => {
                return Err(VaultError::InvalidKeyType.into());
            }
            SecretType::Bls => {
                let bls_secret_key = BlsSecretKey::random(&mut rng).unwrap();
                let public_key =
                    PublicKey::new(BlsPublicKey::from(&bls_secret_key).to_bytes().into());
                let key_id = self.find_id_for_key(&public_key)?;
                let private = SecretKey::new(bls_secret_key.to_bytes().to_vec());

                (private, Some(key_id))
            }
        };
        self.next_id += 1;
        self.entries
            .insert(self.next_id, VaultEntry::new(key_id, attributes, key));

        Ok(Secret::new(self.next_id))
    }

    fn import_secret<D: AsDataSlice>(
        &mut self,
        secret: D,
        attributes: SecretAttributes,
    ) -> ockam_core::Result<Secret> {
        // FIXME: Should we check secrets here?
        self.next_id += 1;
        self.entries.insert(
            self.next_id,
            VaultEntry::new(
                /* FIXME */ None,
                attributes,
                SecretKey::new(secret.as_ref().to_vec()),
            ),
        );
        Ok(Secret::new(self.next_id))
    }

    fn export_secret(&mut self, context: &Secret) -> ockam_core::Result<SecretKey> {
        self.get_entry(context).map(|i| i.key().clone())
    }

    fn load_secret_attributes(&mut self, context: &Secret) -> ockam_core::Result<SecretAttributes> {
        self.get_entry(context).map(|i| i.key_attributes())
    }

    /// Extract public key from secret. Only Curve25519 type is supported
    fn load_public_key_for_secret(&mut self, context: &Secret) -> ockam_core::Result<PublicKey> {
        let entry = self.get_entry(context)?;

        if entry.key().as_ref().len() != CURVE25519_SECRET_LENGTH {
            return Err(VaultError::InvalidPrivateKeyLen.into());
        }

        match entry.key_attributes().stype() {
            SecretType::Curve25519 => {
                let sk = x25519_dalek::StaticSecret::from(*array_ref![
                    entry.key().as_ref(),
                    0,
                    CURVE25519_SECRET_LENGTH
                ]);
                let pk = x25519_dalek::PublicKey::from(&sk);
                Ok(PublicKey::new(pk.to_bytes().to_vec()))
            }
            SecretType::Bls => {
                let bls_secret_key =
                    BlsSecretKey::from_bytes(&entry.key().as_ref().try_into().unwrap()).unwrap();
                Ok(PublicKey::new(
                    BlsPublicKey::from(&bls_secret_key).to_bytes().into(),
                ))
            }
            SecretType::Buffer | SecretType::Aes | SecretType::P256 => {
                Err(VaultError::InvalidKeyType.into())
            }
        }
    }

    /// Remove secret from memory
    fn destroy_secret(&mut self, context: Secret) -> ockam_core::Result<()> {
        if let Some(mut k) = self.entries.remove(&context.index()) {
            k.zeroize();
        }
        Ok(())
    }

    /// Sign data with xeddsa algorithm. Only curve25519 is supported.
    fn sign<D: AsDataSlice>(
        &mut self,
        secret_key: &Secret,
        data: D,
    ) -> ockam_core::Result<SignatureBytes> {
        let entry = self.get_entry(secret_key)?;
        let key = entry.key().as_ref();
        match entry.key_attributes().stype() {
            SecretType::Curve25519 => {
                if key.len() == CURVE25519_SECRET_LENGTH {
                    let mut rng = thread_rng();
                    let mut nonce = [0u8; 64];
                    rng.fill_bytes(&mut nonce);
                    let sig = x25519_dalek::StaticSecret::from(*array_ref!(
                        key,
                        0,
                        CURVE25519_SECRET_LENGTH
                    ))
                    .sign(data.as_ref(), &nonce);
                    Ok(sig)
                } else {
                    Err(VaultError::InvalidKeyType.into())
                }
            }
            SecretType::Bls => {
                unimplemented!()
            }
            SecretType::Buffer | SecretType::Aes | SecretType::P256 => {
                Err(VaultError::InvalidKeyType.into())
            }
        }
    }

    fn encrypt_aead_aes_gcm<P: AsDataSlice, N: AsDataSlice, A: AsDataSlice>(
        &mut self,
        context: &Secret,
        plaintext: P,
        nonce: N,
        aad: A,
    ) -> ockam_core::Result<Data> {
        let entry = self.get_entry(context)?;

        encrypt_impl!(
            entry,
            aad,
            nonce,
            plaintext,
            encrypt,
            VaultError::AeadAesGcmEncrypt
        )
    }

    fn decrypt_aead_aes_gcm<C: AsDataSlice, N: AsDataSlice, A: AsDataSlice>(
        &mut self,
        context: &Secret,
        cipher_text: C,
        nonce: N,
        aad: A,
    ) -> ockam_core::Result<Data> {
        let entry = self.get_entry(context)?;

        encrypt_impl!(
            entry,
            aad,
            nonce,
            cipher_text,
            decrypt,
            VaultError::AeadAesGcmDecrypt
        )
    }

    /// Verify signature with xeddsa algorithm. Only curve25519 is supported.
    fn verify<D: AsDataSlice>(
        &mut self,
        signature: &SignatureBytes,
        public_key: &PublicKey,
        data: D,
    ) -> ockam_core::Result<bool> {
        // FIXME
        if public_key.as_ref().len() == CURVE25519_PUBLIC_LENGTH {
            Ok(x25519_dalek::PublicKey::from(*array_ref!(
                public_key.as_ref(),
                0,
                CURVE25519_PUBLIC_LENGTH
            ))
            .verify(data.as_ref(), signature))
        } else {
            Err(VaultError::InvalidPublicKey.into())
        }
    }
}
