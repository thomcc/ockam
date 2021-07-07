use crate::{Data, KeyId, PublicKey, Secret, SecretAttributes, SignatureBytes, SmallBuffer};
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;

big_array! { BigArray; }

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum VaultRequestMessage {
    Ecdh {
        context: Secret,
        peer_public_key: PublicKey,
    },
    Sha256(Data),
    HkdfSha256 {
        salt: Secret,
        data: Data,
        ikm: Option<Secret>,
        output_attributes: SmallBuffer<SecretAttributes>,
    },
    LoadSecretById(KeyId),
    FindIdForKey(PublicKey),
    GenerateSecret(SecretAttributes),
    ImportSecret {
        secret: Data,
        attributes: SecretAttributes,
    },
    ExportSecret(Secret),
    LoadSecretAttributes(Secret),
    LoadPublicKeyForSecret(Secret),
    DestroySecret(Secret),
    Sign {
        secret_key: Secret,
        data: Data,
    },
    EncryptAeadAesGcm {
        context: Secret,
        plaintext: Data,
        nonce: Data,
        aad: Data,
    },
    DecryptAeadAesGcm {
        context: Secret,
        cipher_text: Data,
        nonce: Data,
        aad: Data,
    },
    Verify {
        #[serde(with = "BigArray")]
        signature: SignatureBytes,
        public_key: PublicKey,
        data: Data,
    },
}
