//! Receiver-side high-level runtime.

use std::sync::{Arc, Mutex};

use bitcoin::{Psbt, Script, Transaction};
use payjoin::persist::OptionalTransitionOutcome;
use payjoin::receive::v2::{
    replay_event_log, Initialized, PayjoinProposal, ReceiveSession, Receiver, ReceiverBuilder,
    SessionEvent, SessionOutcome, UncheckedOriginalPayload,
};
use payjoin::receive::InputPair;
use payjoin::ImplementationError;

use crate::persister::{Capturing, Replay};
use crate::{Error, FeeRange, Step};

/// Wallet capabilities required by [`ReceiverSession`].
///
/// Implementors expose the four wallet-aware decisions the receiver makes:
/// SPK ownership, broadcast suitability of the sender's original transaction,
/// the set of inputs to contribute, and signing of the proposal PSBT. The
/// runtime drives everything else — typestate transitions, polling, the
/// 5-stage check ceremony, finalization.
pub trait ReceiverWallet {
    /// Is the given script-pubkey owned by this wallet?
    ///
    /// Called by both `check_inputs_not_owned` (to refuse a proposal where the
    /// sender claims to spend our outputs) and `identify_receiver_outputs` (to
    /// claim outputs the proposal pays us).
    fn is_owned(&self, spk: &Script) -> bool;

    /// Decide whether the sender's original transaction would be accepted by
    /// mempool policy. Typically a `testmempoolaccept` RPC call.
    fn check_broadcast(&self, tx: &Transaction) -> Result<bool, ImplementationError>;

    /// Produce the inputs to contribute to the payjoin, already shaped as
    /// payjoin [`InputPair`]s.
    ///
    /// Bridge crates (e.g. `bdk_payjoin`) typically provide a helper to build
    /// these from a wallet's candidate set in one line.
    fn contribute(&self) -> Result<Vec<InputPair>, Error>;

    /// Sign and finalize this wallet's contributed inputs in the proposal PSBT.
    ///
    /// The sender's inputs in the same PSBT will remain unsigned — that's
    /// expected. The proposal round-trips back to the sender, who completes
    /// the remaining signatures before broadcast.
    fn process_psbt(&self, psbt: &mut Psbt) -> Result<(), Error>;
}

/// Sans-IO state machine for the payjoin v2 receiver role.
///
/// Drive by alternating [`poll`](Self::poll) (gives you a [`Step`] — what to
/// do next) and [`feed_response`](Self::feed_response) (consume the directory's
/// reply). The session terminates with `Step::Done` after publishing the
/// payjoin proposal back to the directory.
///
/// **Persistence.** Every internal payjoin state advance produces one
/// `SessionEvent`. The runtime buffers events and surfaces them via
/// [`Step::Save`]; the caller decides where/when/how to persist. To resume
/// after a crash, replay the saved log via [`Self::resume_from_events`].
pub struct ReceiverSession<W> {
    wallet: W,
    fee_range: FeeRange,
    ohttp_relay: String,
    pj_uri: String,
    state: Option<State>,
    events: Arc<Mutex<Vec<SessionEvent>>>,
}

// Variants have naturally different sizes (an `Initialized` session is much
// smaller than a fully-constructed `PayjoinProposal`), and at most one variant
// is ever stored at once, so boxing each gains nothing.
#[allow(clippy::large_enum_variant)]
enum State {
    /// Need to GET-poll the directory for the sender's original PSBT.
    ///
    /// `pending_backoff` means the previous poll yielded no payload; the next
    /// [`poll`](ReceiverSession::poll) call should emit [`Step::Backoff`] once
    /// before issuing the next request.
    Polling {
        session: Receiver<Initialized>,
        pending_backoff: bool,
    },
    /// GET sent; awaiting the directory's response body.
    AwaitingPoll {
        session: Receiver<Initialized>,
        ctx: ohttp::ClientResponse,
    },
    /// Original PSBT received and processed; ready to POST the proposal.
    Posting(Receiver<PayjoinProposal>),
    /// POST sent; awaiting acknowledgement.
    AwaitingPostAck,
    /// Terminal success.
    Done,
    /// Terminal failure.
    Failed(Option<Error>),
}

impl<W: ReceiverWallet> ReceiverSession<W> {
    /// Build a new session.
    pub fn new(
        builder: ReceiverBuilder,
        ohttp_relay: impl Into<String>,
        wallet: W,
        fee_range: FeeRange,
    ) -> Result<Self, Error> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let persister = Capturing::new(events.clone());
        let session = builder.build().save(&persister).map_err(Error::payjoin)?;
        let pj_uri = session.pj_uri().to_string();
        Ok(Self {
            wallet,
            fee_range,
            ohttp_relay: ohttp_relay.into(),
            pj_uri,
            state: Some(State::Polling {
                session,
                pending_backoff: false,
            }),
            events,
        })
    }

    /// Resume a session from a previously-persisted event log.
    ///
    /// `events` should be the complete sequence of session events as they were
    /// recorded from [`Step::Save`], in order. The runtime replays them through
    /// payjoin's state machine to reconstruct the receiver's current state, then
    /// continues from there.
    ///
    /// # Atomic-persistence requirement
    ///
    /// Each `Step::Save` may carry multiple events that represent one logical
    /// state advance (in particular, processing the sender's original PSBT
    /// emits 9 events). They must be persisted **atomically as a batch**. If
    /// the saved log ends partway through such a batch — e.g. it contains
    /// `CheckedBroadcastSuitability` but not the subsequent events — this
    /// function returns an error, since the state machine has no clean
    /// re-entry point in the middle of `process_original`.
    pub fn resume_from_events(
        events: Vec<SessionEvent>,
        ohttp_relay: impl Into<String>,
        wallet: W,
        fee_range: FeeRange,
    ) -> Result<Self, Error> {
        let persister = Replay::new(events);
        let (session, history) =
            replay_event_log(&persister).map_err(|e| Error::payjoin(format!("{e:?}")))?;
        let pj_uri = history.pj_uri().to_string();

        let state = match session {
            ReceiveSession::Initialized(s) => State::Polling {
                session: s,
                pending_backoff: false,
            },
            ReceiveSession::PayjoinProposal(s) => State::Posting(s),
            ReceiveSession::Closed(SessionOutcome::Success(_)) => State::Done,
            ReceiveSession::Closed(outcome) => State::Failed(Some(Error::Payjoin(format!(
                "session previously closed: {outcome:?}"
            )))),
            // Any other variant means the event log ended mid-`process_original`,
            // violating the atomic-persistence requirement. We refuse to resume
            // because the state machine has no clean re-entry point.
            other => {
                return Err(Error::Payjoin(format!(
                    "cannot resume from intermediate state {other:?}; event log was not \
                     persisted atomically per `Step::Save` batch"
                )));
            }
        };

        Ok(Self {
            wallet,
            fee_range,
            ohttp_relay: ohttp_relay.into(),
            pj_uri,
            state: Some(state),
            events: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// The BIP-21 / BIP-77 URI the receiver should share with the sender out of band.
    pub fn pj_uri(&self) -> &str {
        &self.pj_uri
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
            State::Polling {
                session,
                pending_backoff: true,
            } => (
                State::Polling {
                    session,
                    pending_backoff: false,
                },
                Step::Backoff,
            ),
            State::Polling {
                session,
                pending_backoff: false,
            } => match session.create_poll_request(self.ohttp_relay.as_str()) {
                Ok((req, ctx)) => (State::AwaitingPoll { session, ctx }, Step::SendRequest(req)),
                Err(e) => (State::Failed(None), Step::Failed(Error::payjoin(e))),
            },
            State::Posting(proposal) => {
                match proposal.create_post_request(self.ohttp_relay.as_str()) {
                    Ok((req, _ctx)) => (State::AwaitingPostAck, Step::SendRequest(req)),
                    Err(e) => (State::Failed(None), Step::Failed(Error::payjoin(e))),
                }
            }
            State::AwaitingPoll { .. } | State::AwaitingPostAck => (
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

    fn consume(&self, state: State, bytes: Vec<u8>) -> State {
        match state {
            State::AwaitingPoll { session, ctx } => {
                let persister = self.persister();
                let outcome = match session.process_response(&bytes, ctx).save(&persister) {
                    Ok(o) => o,
                    Err(e) => return State::Failed(Some(Error::payjoin(e))),
                };
                match outcome {
                    OptionalTransitionOutcome::Stasis(session) => State::Polling {
                        session,
                        pending_backoff: true,
                    },
                    OptionalTransitionOutcome::Progress(unchecked) => {
                        match self.process_original(unchecked) {
                            Ok(proposal) => State::Posting(proposal),
                            Err(e) => State::Failed(Some(e)),
                        }
                    }
                }
            }
            State::AwaitingPostAck => State::Done,
            _ => State::Failed(Some(Error::Payjoin(
                "feed_response called in an unexpected state".into(),
            ))),
        }
    }

    fn process_original(
        &self,
        unchecked: Receiver<UncheckedOriginalPayload>,
    ) -> Result<Receiver<PayjoinProposal>, Error> {
        let persister = self.persister();
        let wallet = &self.wallet;

        let p = unchecked
            .check_broadcast_suitability(None, |tx| wallet.check_broadcast(tx))
            .save(&persister)
            .map_err(Error::payjoin)?;
        let p = p
            .check_inputs_not_owned(&mut |spk| Ok(wallet.is_owned(spk)))
            .save(&persister)
            .map_err(Error::payjoin)?;
        let p = p
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .save(&persister)
            .map_err(Error::payjoin)?;
        let p = p
            .identify_receiver_outputs(&mut |spk| Ok(wallet.is_owned(spk)))
            .save(&persister)
            .map_err(Error::payjoin)?;
        let p = p.commit_outputs().save(&persister).map_err(Error::payjoin)?;

        let inputs = wallet.contribute()?;
        if inputs.is_empty() {
            return Err(Error::Wallet("no candidate inputs to contribute".into()));
        }
        let selected = p
            .try_preserving_privacy(inputs)
            .map_err(|e| Error::Payjoin(format!("privacy-preserving selection: {e:?}")))?;
        let p = p
            .contribute_inputs(vec![selected])
            .map_err(|e| Error::Payjoin(format!("contribute_inputs: {e:?}")))?
            .commit_inputs()
            .save(&persister)
            .map_err(Error::payjoin)?;

        let p = p
            .apply_fee_range(self.fee_range.min, self.fee_range.max)
            .save(&persister)
            .map_err(Error::payjoin)?;

        let p = p
            .finalize_proposal(|psbt: &Psbt| {
                let mut psbt = psbt.clone();
                wallet
                    .process_psbt(&mut psbt)
                    .map_err(|e| ImplementationError::from(e.to_string().as_str()))?;
                Ok(psbt)
            })
            .save(&persister)
            .map_err(Error::payjoin)?;

        Ok(p)
    }
}
