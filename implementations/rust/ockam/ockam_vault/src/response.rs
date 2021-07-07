use crate::{
    Data, HashBytes, KeyId, PublicKey, Secret, SecretAttributes, SecretKey, SignatureBytes,
    SmallBuffer,
};
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;

big_array! { BigArray; }

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum VaultResponseMessage {
    Ecdh(Secret),
    Sha256(HashBytes),
    HkdfSha256(SmallBuffer<Secret>),
    LoadSecretById(Secret),
    FindIdForKey(KeyId),
    GenerateSecret(Secret),
    ImportSecret(Secret),
    ExportSecret(SecretKey),
    LoadSecretAttributes(SecretAttributes),
    LoadPublicKeyForSecret(PublicKey),
    DestroySecret,
    Sign(#[serde(with = "BigArray")] SignatureBytes),
    EncryptAeadAesGcm(Data),
    DecryptAeadAesGcm(Data),
    Verify(bool),
}
