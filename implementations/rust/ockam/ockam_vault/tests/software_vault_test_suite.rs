use ockam_test::VaultTests;
use ockam_vault::SoftwareVault;

#[test]
fn software_vault_trait_tests() {
    let mut vault = SoftwareVault::new();
    VaultTests::run_tests(&mut vault).unwrap();
}
