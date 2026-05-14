//! Sans-IO state machines for the payjoin v2 protocol.
//!
//! `payjoin_runtime` exposes a driver per role ([`ReceiverSession`],
//! [`SenderSession`]) that owns the multi-stage payjoin typestate, the OHTTP
//! polling cycle, and the `.save(&persister)` ceremony. The caller drives each
//! session by exchanging [`Request`] / response bytes with their preferred HTTP
//! transport and supplies wallet-aware decisions through the [`ReceiverWallet`]
//! / [`SenderWallet`] traits.
//!
//! The runtime is wallet-agnostic: it depends only on `payjoin`, `bitcoin`, and
//! `bitcoin-ohttp`. Bridge crates (e.g. `bdk_payjoin`) layer wallet ergonomics
//! on top.
//!
//! # Sketch
//!
//! ```ignore
//! let mut session = ReceiverSession::new(builder, relay, wallet, fee_range)?;
//! loop {
//!     match session.poll() {
//!         Step::SendRequest(req) => {
//!             let resp = http.post(req).await?;
//!             session.feed_response(resp.bytes().to_vec())?;
//!         }
//!         Step::Backoff => sleep(Duration::from_secs(2)).await,
//!         Step::Done => break,
//!         Step::Failed(e) => return Err(e.into()),
//!     }
//! }
//! ```

#![warn(missing_docs)]

mod error;
mod psbt;
mod receiver;
mod sender;

pub use error::Error;
pub use psbt::restore_psbt_utxos;
pub use receiver::{ReceiverSession, ReceiverWallet};
pub use sender::{SenderSession, SenderWallet};

// Re-exports so consumers can build the runtime's inputs without a direct
// `payjoin` dependency.
pub use payjoin::receive::v2::ReceiverBuilder;
pub use payjoin::receive::InputPair;
pub use payjoin::send::v2::SenderBuilder;
pub use payjoin::{ImplementationError, OhttpKeys, PjUri, Request, Uri, UriExt};

use bitcoin::FeeRate;

/// Output of [`ReceiverSession::poll`] / [`SenderSession::poll`] — what the
/// caller should do to drive the state machine forward.
#[derive(Debug)]
pub enum Step {
    /// Send this HTTP request, then feed the response body back via
    /// `feed_response`.
    SendRequest(Request),
    /// The directory had no payload yet. Sleep, then call `poll` again. The
    /// runtime never enforces a specific delay — pick what's appropriate for
    /// your context (a few seconds is conventional).
    Backoff,
    /// The session reached its terminal success state. For the sender, the
    /// finalized transaction is now available via
    /// [`SenderSession::final_tx`](crate::SenderSession::final_tx).
    Done,
    /// The session failed terminally. Subsequent `poll` calls will return
    /// [`Error::Terminated`].
    Failed(Error),
}

/// Fee-range bounds passed by the receiver to payjoin's `apply_fee_range`.
///
/// Both endpoints are optional: `None` for `min` means "accept payjoin's
/// recommended minimum (broadcast-min)"; `None` for `max` means "the receiver
/// will not pay for any of the network fee".
#[derive(Debug, Clone, Copy, Default)]
pub struct FeeRange {
    /// Minimum effective feerate the receiver accepts on the proposal.
    pub min: Option<FeeRate>,
    /// Maximum effective feerate the receiver is willing to pay for their own
    /// contributed input/output. `None` opts out of receiver-paid fees.
    pub max: Option<FeeRate>,
}
