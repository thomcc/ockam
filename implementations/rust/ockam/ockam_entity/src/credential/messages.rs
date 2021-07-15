use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum CredentialProtocolMessage {
    IssueOfferRequest(String),
    IssueOffer(crate::CredentialOffer),
    IssueRequest(crate::CredentialRequest, Vec<crate::CredentialAttribute>),
    IssueResponse(crate::CredentialFragment2),
    PresentationOffer,
    PresentationRequest(crate::ProofRequestId),
    PresentationResponse(crate::CredentialPresentation),
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PresentationFinishedMessage;
