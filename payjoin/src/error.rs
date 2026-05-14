use core::fmt;

/// Errors surfaced by the runtime.
///
/// `Error` is intentionally coarse: the underlying payjoin crate has a deep error
/// hierarchy, but the runtime collapses it into three semantic buckets to keep
/// match arms manageable. The original error message is preserved in the
/// `Payjoin(_)` / `Wallet(_)` payloads for diagnostics.
#[derive(Debug)]
pub enum Error {
    /// A payjoin protocol-level error (encapsulation, directory response,
    /// state-machine violation, etc.).
    Payjoin(String),
    /// A wallet-side failure raised by a [`ReceiverWallet`](crate::ReceiverWallet)
    /// or [`SenderWallet`](crate::SenderWallet) callback.
    Wallet(String),
    /// PSBT finalization did not complete (one or more inputs unfinalized).
    FinalizeFailed,
    /// The session has already terminated (Done or Failed). All subsequent
    /// `poll` / `feed_response` calls return this error.
    Terminated,
}

impl Error {
    pub(crate) fn payjoin<E: fmt::Display>(e: E) -> Self {
        Self::Payjoin(e.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Payjoin(s) => write!(f, "payjoin protocol error: {s}"),
            Error::Wallet(s) => write!(f, "wallet error: {s}"),
            Error::FinalizeFailed => write!(f, "failed to finalize PSBT"),
            Error::Terminated => write!(f, "session already terminated"),
        }
    }
}

impl std::error::Error for Error {}
