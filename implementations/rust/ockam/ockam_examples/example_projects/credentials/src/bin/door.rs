use lib::{
    read_line, DOOR_LISTENER_ADDRESS, DOOR_TCP_ADDRESS, DOOR_WORKER_ADDRESS,
    OFFICE_LISTENER_ADDRESS, OFFICE_TCP_ADDRESS,
};
use ockam::{
    credential_attribute_values, credential_type, route, Context, CredentialProtocol, Entity,
    EntityIdentifier, IdentifierTrustPolicy, Identity, NoOpTrustPolicy, Result, SecureChannels,
    TcpTransport, TCP,
};
use std::convert::TryFrom;

#[ockam::node]
async fn main(ctx: Context) -> Result<()> {
    // Create a Door (Verifier) that trusts the Office, and will checks Bob's (Holder) credentials.
    let mut entity = Entity::create(&ctx)?;

    println!("Door id: {}", entity.identifier()?);

    println!("Enter Office id: ");
    let office_id = read_line();
    let office_id = EntityIdentifier::try_from(office_id.as_str())?;

    let tcp = TcpTransport::create(&ctx).await?;
    tcp.connect(OFFICE_TCP_ADDRESS).await?;

    // Just to get office's profile
    let _office_channel = entity.create_secure_channel(
        route![(TCP, OFFICE_TCP_ADDRESS), OFFICE_LISTENER_ADDRESS],
        IdentifierTrustPolicy::new(office_id.clone()),
    )?;

    entity.create_secure_channel_listener(DOOR_LISTENER_ADDRESS, NoOpTrustPolicy {})?;

    // TODO: Add listener
    tcp.listen(DOOR_TCP_ADDRESS).await?;

    let res = entity.verify_credential(
        DOOR_WORKER_ADDRESS,
        &office_id,
        credential_type!["TYPE_ID"; "door_id", (Number, "can_open_door")],
        credential_attribute_values![entity.identifier()?.to_string(), 1],
    )?;
    assert!(res);

    println!("Door is opened!");

    Ok(())
}
