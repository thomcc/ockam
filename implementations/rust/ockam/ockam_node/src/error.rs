/// Error declarations.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Unable to gracefully stop the Node.
    FailedStopNode,
    /// Unable to start a worker
    FailedStartWorker,
}

impl Error {
    /// Integer code associated with the error domain.
    pub const DOMAIN_CODE: u32 = 11_000;
    /// Descriptive name for the error domain.
    pub const DOMAIN_NAME: &'static str = "OCKAM_NODE";
}

impl Into<ockam_core::Error> for Error {
    fn into(self) -> ockam_core::Error {
        ockam_core::Error::new(Self::DOMAIN_CODE + (self as u32), Self::DOMAIN_NAME)
    }
}
