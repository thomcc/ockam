use ockam_core::hex::{decode, encode};
use ockam_vault::*;

pub fn ecdh(vault: &mut impl VaultTrait) {
    let attributes = SecretAttributes::new(
        SecretType::Curve25519,
        SecretPersistence::Ephemeral,
        CURVE25519_SECRET_LENGTH,
    );
    let sk_ctx_1 = vault.generate_secret(attributes).unwrap();
    let sk_ctx_2 = vault.generate_secret(attributes).unwrap();
    let pk_1 = vault.load_public_key_for_secret(&sk_ctx_1).unwrap();
    let pk_2 = vault.load_public_key_for_secret(&sk_ctx_2).unwrap();

    let res1 = vault.ecdh(&sk_ctx_1, &pk_2);
    assert!(res1.is_ok());
    let _ss1 = res1.unwrap();

    let res2 = vault.ecdh(&sk_ctx_2, &pk_1);
    assert!(res2.is_ok());
    let _ss2 = res2.unwrap();
    // TODO: Check result against test vector
}

pub fn sha256(vault: &mut impl VaultTrait) {
    let res = vault.sha256(b"a");
    assert!(res.is_ok());
    let digest = res.unwrap();
    assert_eq!(
        encode(digest),
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    );
}

pub fn hkdf(vault: &mut impl VaultTrait) {
    let salt_value = b"hkdf_test";
    let attributes = SecretAttributes::new(
        SecretType::Buffer,
        SecretPersistence::Ephemeral,
        salt_value.len(),
    );
    let salt = vault.import_secret(&salt_value[..], attributes).unwrap();

    let ikm_value = b"a";
    let attributes = SecretAttributes::new(
        SecretType::Buffer,
        SecretPersistence::Ephemeral,
        ikm_value.len(),
    );
    let ikm = vault.import_secret(&ikm_value[..], attributes).unwrap();

    let attributes = SecretAttributes::new(SecretType::Buffer, SecretPersistence::Ephemeral, 24);

    let res = vault.hkdf_sha256(&salt, b"", Some(&ikm), vec![attributes]);
    assert!(res.is_ok());
    let digest = res.unwrap();
    assert_eq!(digest.len(), 1);
    let digest = vault.export_secret(&digest[0]).unwrap();
    assert_eq!(
        encode(digest.as_ref()),
        "921ab9f260544b71941dbac2ca2d42c417aa07b53e055a8f"
    );
}

pub fn find_id_for_key(vault: &mut impl VaultTrait) {
    let public =
        decode("68858ea1ea4e1ade755df7fb6904056b291d9781eb5489932f46e32f12dd192a").unwrap();
    let public = PublicKey::new(public.to_vec());

    let key_id = vault.find_id_for_key(&public).unwrap();

    assert_eq!(
        key_id,
        "732af49a0b47c820c0a4cac428d6cb80c1fa70622f4a51708163dd87931bc942"
    );
}

pub fn load_secret_by_id(vault: &mut impl VaultTrait) {
    let attributes = SecretAttributes::new(
        SecretType::Curve25519,
        SecretPersistence::Ephemeral,
        CURVE25519_SECRET_LENGTH,
    );

    let secret = vault.generate_secret(attributes).unwrap();
    let public = vault.load_public_key_for_secret(&secret).unwrap();

    let key_id = vault.find_id_for_key(&public).unwrap();
    let secret2 = vault.load_secret_by_id(&key_id).unwrap();

    assert_eq!(secret.index(), secret2.index());
}

pub fn generate_public_keys(vault: &mut impl VaultTrait) {
    let attributes = SecretAttributes::new(
        SecretType::Curve25519,
        SecretPersistence::Ephemeral,
        CURVE25519_SECRET_LENGTH,
    );

    let res = vault.generate_secret(attributes);
    assert!(res.is_ok());
    let p256_ctx_1 = res.unwrap();

    let res = vault.load_public_key_for_secret(&p256_ctx_1);
    assert!(res.is_ok());
    let pk_1 = res.unwrap();
    assert_eq!(pk_1.as_ref().len(), CURVE25519_PUBLIC_LENGTH);

    let res = vault.generate_secret(attributes);
    assert!(res.is_ok());
    let c25519_ctx_1 = res.unwrap();
    let res = vault.load_public_key_for_secret(&c25519_ctx_1);
    assert!(res.is_ok());
    let pk_1 = res.unwrap();
    assert_eq!(pk_1.as_ref().len(), CURVE25519_PUBLIC_LENGTH);
}

pub fn generate_secret_keys(vault: &mut impl VaultTrait) {
    let types = [(SecretType::Curve25519, 32), (SecretType::Buffer, 24)];
    for (t, s) in &types {
        let attributes = SecretAttributes::new(*t, SecretPersistence::Ephemeral, *s);
        let res = vault.generate_secret(attributes);
        assert!(res.is_ok());
        let sk_ctx = res.unwrap();
        let sk = vault.export_secret(&sk_ctx).unwrap();
        assert_eq!(sk.as_ref().len(), *s);
        vault.destroy_secret(sk_ctx).unwrap();
    }
}

pub fn import_export_secret(vault: &mut impl VaultTrait) {
    let attributes = SecretAttributes::new(
        SecretType::Curve25519,
        SecretPersistence::Ephemeral,
        CURVE25519_SECRET_LENGTH,
    );

    let secret_str = "98d589b0dce92c9e2442b3093718138940bff71323f20b9d158218b89c3cec6e";

    let secret = vault
        .import_secret(decode(secret_str).unwrap().as_slice(), attributes)
        .unwrap();

    let first_secret_index = secret.index();
    assert!(first_secret_index > 0);
    assert_eq!(
        encode(vault.export_secret(&secret).unwrap().as_ref()),
        secret_str
    );

    let attributes = SecretAttributes::new(SecretType::Buffer, SecretPersistence::Ephemeral, 24);
    let secret_str = "5f791cc52297f62c7b8829b15f828acbdb3c613371d21aa1";
    let secret = vault
        .import_secret(decode(secret_str).unwrap().as_slice(), attributes)
        .unwrap();

    assert_eq!(secret.index(), first_secret_index + 1);

    assert_eq!(
        encode(vault.export_secret(&secret).unwrap().as_ref()),
        secret_str
    );
}

pub fn load_secret_attributes(vault: &mut impl VaultTrait) {
    let attributes = SecretAttributes::new(
        SecretType::Curve25519,
        SecretPersistence::Ephemeral,
        CURVE25519_SECRET_LENGTH,
    );

    let secret = vault.generate_secret(attributes).unwrap();
    assert_eq!(vault.load_secret_attributes(&secret).unwrap(), attributes);

    let attributes = SecretAttributes::new(SecretType::Buffer, SecretPersistence::Ephemeral, 24);

    let secret = vault.generate_secret(attributes).unwrap();
    assert_eq!(vault.load_secret_attributes(&secret).unwrap(), attributes);
}

pub fn sign(vault: &mut impl VaultTrait) {
    let secret = vault
        .generate_secret(SecretAttributes::new(
            SecretType::Curve25519,
            SecretPersistence::Ephemeral,
            CURVE25519_SECRET_LENGTH,
        ))
        .unwrap();
    let res = vault.sign(&secret, b"hello world!");
    assert!(res.is_ok());
    let pubkey = vault.load_public_key_for_secret(&secret).unwrap();
    let signature = res.unwrap();
    let res = vault.verify(&signature, &pubkey, b"hello world!").unwrap();
    assert!(res);
}

pub fn encrypt_decrypt(vault: &mut impl VaultTrait) {
    let message = b"Ockam Test Message";
    let nonce = b"TestingNonce";
    let aad = b"Extra payload data";
    let attributes = SecretAttributes::new(
        SecretType::Aes,
        SecretPersistence::Ephemeral,
        AES128_SECRET_LENGTH,
    );

    let ctx = &vault.generate_secret(attributes).unwrap();
    let res = vault.encrypt_aead_aes_gcm(ctx, message.as_ref(), nonce.as_ref(), aad.as_ref());
    assert!(res.is_ok());
    let mut ciphertext = res.unwrap();
    let res = vault.decrypt_aead_aes_gcm(ctx, ciphertext.as_slice(), nonce.as_ref(), aad.as_ref());
    assert!(res.is_ok());
    let plaintext = res.unwrap();
    assert_eq!(plaintext, message.to_vec());
    ciphertext[0] ^= 0xb4;
    ciphertext[1] ^= 0xdc;
    let res = vault.decrypt_aead_aes_gcm(ctx, ciphertext.as_slice(), nonce.as_ref(), aad.as_ref());
    assert!(res.is_err());
}

pub struct VaultTests;

impl VaultTests {
    pub fn run_tests(test_item: &mut impl VaultTrait) -> ockam_core::Result<()> {
        ecdh(test_item);
        sha256(test_item);
        hkdf(test_item);
        find_id_for_key(test_item);
        load_secret_by_id(test_item);
        generate_public_keys(test_item);
        generate_secret_keys(test_item);
        import_export_secret(test_item);
        sign(test_item);
        encrypt_decrypt(test_item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::VaultTests;
    use ockam_vault::SoftwareVault;
}
