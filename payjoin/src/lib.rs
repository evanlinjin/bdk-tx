//! High-level sans-IO runtime for the payjoin v2 protocol, integrated with `bdk_tx`.
//!
//! `bdk_payjoin` exposes a driver per role ([`ReceiverSession`], [`SenderSession`])
//! that owns the multi-stage payjoin typestate, the OHTTP polling cycle, and the
//! `.save(&persister)` ceremony. The caller drives each session by exchanging
//! [`Request`] / response bytes with their preferred HTTP transport and supplies
//! wallet-aware decisions through the [`ReceiverWallet`] / [`SenderWallet`] traits.
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
//!
//! For users who want to drive the payjoin state machine manually, the lower-level
//! glue ([`input_pair_from`], [`input_pairs_from`], [`restore_psbt_utxos`]) is also
//! exposed.

#![warn(missing_docs)]

mod error;
mod psbt;
mod receiver;
mod sender;

pub use error::Error;
pub use psbt::restore_psbt_utxos;
pub use receiver::{ReceiverSession, ReceiverWallet};
pub use sender::{SenderSession, SenderWallet};

// Re-exports for callers so they don't need to depend on `payjoin` directly.
pub use payjoin::receive::v2::ReceiverBuilder;
pub use payjoin::send::v2::SenderBuilder;
pub use payjoin::{ImplementationError, OhttpKeys, PjUri, Request, Uri, UriExt};

use bdk_tx::{Input, InputCandidates};
use bitcoin::{FeeRate, Sequence};
use payjoin::receive::InputPair;

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

/// Convert a single [`Input`] into a payjoin [`InputPair`].
///
/// Handles the P2TR / P2WSH weight quirk: [`InputPair::new`] cannot infer the
/// witness weight for an unsigned taproot or witness-script-hash input, so we
/// pass the explicit weight derived from the input's spending plan. For input
/// types it *can* infer (P2WPKH, P2PKH, nested P2SH-P2WPKH) we pass `None`
/// because passing `Some` would be rejected as `ProvidedUnnecessaryWeight`.
///
/// `fallback_sequence` is used when the input's plan does not pin a specific
/// sequence (e.g. no relative timelock). Pass
/// [`Sequence::ENABLE_RBF_NO_LOCKTIME`] for the conventional payjoin case.
///
/// Returns `None` if payjoin rejects the input (e.g. the script type is
/// unsupported, the prev_tx / witness_utxo are missing, etc.).
pub fn input_pair_from(input: &Input, fallback_sequence: Sequence) -> Option<InputPair> {
    let spk = &input.prev_txout().script_pubkey;
    let needs_explicit_weight = spk.is_p2tr() || spk.is_p2wsh();
    let expected_weight = needs_explicit_weight.then(|| input.expected_input_weight());
    let (txin, psbt_input) = input.to_psbt_pair(fallback_sequence);
    InputPair::new(txin, psbt_input, expected_weight).ok()
}

/// Convert every input in `candidates` into a payjoin [`InputPair`].
///
/// Inputs that payjoin rejects are silently dropped.
pub fn input_pairs_from(
    candidates: &InputCandidates,
    fallback_sequence: Sequence,
) -> Vec<InputPair> {
    candidates
        .inputs()
        .filter_map(|input| input_pair_from(input, fallback_sequence))
        .collect()
}
