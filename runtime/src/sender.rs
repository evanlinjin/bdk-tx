//! Sender-side high-level runtime.

use std::sync::{Arc, Mutex};

use bitcoin::{Amount, FeeRate, Psbt, Transaction};
use payjoin::persist::OptionalTransitionOutcome;
use payjoin::send::v2::{
    PollingForProposal, Sender, SenderBuilder, SessionEvent, WithReplyKey,
};
use payjoin::PjUri;

use crate::persister::Capturing;
use crate::{Error, Step};

/// Wallet capabilities required by [`SenderSession`].
///
/// The sender's only wallet-aware operation is processing the payjoin proposal
/// PSBT: restoring any sanitized UTXO fields, signing the sender's inputs, and
/// finalizing the PSBT for extraction. The runtime drives everything else.
pub trait SenderWallet {
    /// Process the proposal PSBT in place.
    ///
    /// The implementation is responsible for three things, in order:
    /// 1. Restoring `witness_utxo` / `non_witness_utxo` on the sender's inputs
    ///    if the proposal sanitized them away (see [`restore_psbt_utxos`]).
    /// 2. Signing the sender's inputs.
    /// 3. Finalizing every input (the receiver should already have finalized
    ///    theirs; this call finalizes the sender's). After this returns, the
    ///    runtime calls `psbt.extract_tx()`, so the PSBT must be fully ready.
    ///
    /// Bridge crates typically provide a one-call helper that does all three.
    ///
    /// [`restore_psbt_utxos`]: crate::restore_psbt_utxos
    fn process_psbt(&self, psbt: &mut Psbt) -> Result<(), Error>;
}

/// Sans-IO state machine for the payjoin v2 sender role.
///
/// Drive by alternating [`poll`](Self::poll) and
/// [`feed_response`](Self::feed_response). When the session reaches
/// `Step::Done`, the broadcastable transaction is available via
/// [`final_tx`](Self::final_tx) and the network fee via [`fee`](Self::fee).
///
/// **Persistence.** Every internal payjoin state advance produces one
/// `SessionEvent`. The runtime buffers events and surfaces them via
/// [`Step::Save`]; the caller decides where/when/how to persist. To resume
/// after a crash, replay the saved log via [`Self::resume_from_events`].
pub struct SenderSession<W> {
    wallet: W,
    ohttp_relay: String,
    state: Option<State>,
    result: Option<(Transaction, Amount)>,
    events: Arc<Mutex<Vec<SessionEvent>>>,
}

// See the note on `receiver::State`.
#[allow(clippy::large_enum_variant)]
enum State {
    /// Need to POST the original PSBT to the directory.
    PostingOriginal(Sender<WithReplyKey>),
    /// POST sent; awaiting acknowledgement.
    AwaitingPostAck {
        session: Sender<WithReplyKey>,
        ctx: ohttp::ClientResponse,
    },
    /// Need to GET-poll the directory for the receiver's proposal.
    PollingProposal {
        session: Sender<PollingForProposal>,
        pending_backoff: bool,
    },
    /// GET sent; awaiting the directory's response.
    AwaitingProposalPoll {
        session: Sender<PollingForProposal>,
        ctx: ohttp::ClientResponse,
    },
    /// Terminal success.
    Done,
    /// Terminal failure.
    Failed(Option<Error>),
}

impl<W: SenderWallet> SenderSession<W> {
    /// Build a new sender session.
    ///
    /// `psbt` is the sender's original (signed and finalized) PSBT paying `uri`.
    /// `min_fee_rate` is the lowest feerate the sender will accept in the
    /// counterparty's proposal.
    pub fn new(
        psbt: Psbt,
        uri: PjUri,
        ohttp_relay: impl Into<String>,
        wallet: W,
        min_fee_rate: FeeRate,
    ) -> Result<Self, Error> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let persister = Capturing::new(events.clone());
        let session = SenderBuilder::new(psbt, uri)
            .build_recommended(min_fee_rate)
            .map_err(Error::payjoin)?
            .save(&persister)
            .map_err(Error::payjoin)?;
        Ok(Self {
            wallet,
            ohttp_relay: ohttp_relay.into(),
            state: Some(State::PostingOriginal(session)),
            result: None,
            events,
        })
    }

    /// Resume a session from a previously-persisted event log.
    ///
    /// `events` should be the complete sequence of session events as they were
    /// recorded from [`Step::Save`], in order. The runtime replays them through
    /// payjoin's state machine to reconstruct the sender's current state, then
    /// continues from there.
    ///
    /// Currently stubbed — see issue tracker.
    pub fn resume_from_events(
        _events: Vec<SessionEvent>,
        _ohttp_relay: impl Into<String>,
        _wallet: W,
        _min_fee_rate: FeeRate,
    ) -> Result<Self, Error> {
        Err(Error::Payjoin(
            "resume_from_events is not yet implemented".into(),
        ))
    }

    /// The broadcastable transaction, once the session has reached `Step::Done`.
    pub fn final_tx(&self) -> Option<&Transaction> {
        self.result.as_ref().map(|(t, _)| t)
    }

    /// The network fee, once the session has reached `Step::Done`.
    pub fn fee(&self) -> Option<Amount> {
        self.result.as_ref().map(|(_, f)| *f)
    }

    /// Consume the session and return the wallet adapter.
    pub fn into_wallet(self) -> W {
        self.wallet
    }

    /// Advance the state machine and report what the caller should do next.
    pub fn poll(&mut self) -> Step<SessionEvent> {
        // Drain any captured events first — the caller must persist them
        // before we issue any further side-effecting requests.
        let drained = self.drain_events();
        if !drained.is_empty() {
            return Step::Save(drained);
        }

        let state = match self.state.take() {
            Some(s) => s,
            None => return Step::Failed(Error::Terminated),
        };
        let (next, step) = self.step(state);
        self.state = Some(next);
        step
    }

    /// Feed back the body of the directory response from the most recent
    /// `Step::SendRequest`.
    pub fn feed_response(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let state = self.state.take().ok_or(Error::Terminated)?;
        let next = self.consume(state, bytes);
        self.state = Some(next);
        Ok(())
    }

    fn drain_events(&self) -> Vec<SessionEvent> {
        self.events
            .lock()
            .expect("captured-events mutex poisoned")
            .drain(..)
            .collect()
    }

    fn persister(&self) -> Capturing<SessionEvent> {
        Capturing::new(self.events.clone())
    }

    fn step(&self, state: State) -> (State, Step<SessionEvent>) {
        match state {
            State::PostingOriginal(session) => {
                match session.create_v2_post_request(self.ohttp_relay.as_str()) {
                    Ok((req, ctx)) => (
                        State::AwaitingPostAck { session, ctx },
                        Step::SendRequest(req),
                    ),
                    Err(e) => (State::Failed(None), Step::Failed(Error::payjoin(e))),
                }
            }
            State::PollingProposal {
                session,
                pending_backoff: true,
            } => (
                State::PollingProposal {
                    session,
                    pending_backoff: false,
                },
                Step::Backoff,
            ),
            State::PollingProposal {
                session,
                pending_backoff: false,
            } => match session.create_poll_request(self.ohttp_relay.as_str()) {
                Ok((req, ctx)) => (
                    State::AwaitingProposalPoll { session, ctx },
                    Step::SendRequest(req),
                ),
                Err(e) => (State::Failed(None), Step::Failed(Error::payjoin(e))),
            },
            State::AwaitingPostAck { .. } | State::AwaitingProposalPoll { .. } => (
                state,
                Step::Failed(Error::Payjoin(
                    "called poll() while awaiting a response".into(),
                )),
            ),
            State::Done => (State::Done, Step::Done),
            State::Failed(opt) => {
                let err = opt.unwrap_or(Error::Terminated);
                (State::Failed(None), Step::Failed(err))
            }
        }
    }

    fn consume(&mut self, state: State, bytes: Vec<u8>) -> State {
        match state {
            State::AwaitingPostAck { session, ctx } => {
                let persister = self.persister();
                match session.process_response(&bytes, ctx).save(&persister) {
                    Ok(next) => State::PollingProposal {
                        session: next,
                        pending_backoff: false,
                    },
                    Err(e) => State::Failed(Some(Error::payjoin(e))),
                }
            }
            State::AwaitingProposalPoll { session, ctx } => {
                let persister = self.persister();
                let outcome = match session.process_response(&bytes, ctx).save(&persister) {
                    Ok(o) => o,
                    Err(e) => return State::Failed(Some(Error::payjoin(e))),
                };
                match outcome {
                    OptionalTransitionOutcome::Stasis(session) => State::PollingProposal {
                        session,
                        pending_backoff: true,
                    },
                    OptionalTransitionOutcome::Progress(psbt) => match self.finalize(psbt) {
                        Ok((tx, fee)) => {
                            self.result = Some((tx, fee));
                            State::Done
                        }
                        Err(e) => State::Failed(Some(e)),
                    },
                }
            }
            _ => State::Failed(Some(Error::Payjoin(
                "feed_response called in an unexpected state".into(),
            ))),
        }
    }

    fn finalize(&self, mut psbt: Psbt) -> Result<(Transaction, Amount), Error> {
        let fee = psbt.fee().map_err(Error::payjoin)?;
        self.wallet.process_psbt(&mut psbt)?;
        let tx = psbt
            .extract_tx()
            .map_err(|e| Error::Wallet(format!("extract_tx after process_psbt: {e}")))?;
        Ok((tx, fee))
    }
}
