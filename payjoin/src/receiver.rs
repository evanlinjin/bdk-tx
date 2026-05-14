//! Receiver-side high-level runtime.

use bdk_tx::{Finalizer, InputCandidates};
use bitcoin::{OutPoint, Psbt, Script, Sequence, Transaction};
use miniscript::plan::Plan;
use payjoin::persist::{NoopSessionPersister, OptionalTransitionOutcome};
use payjoin::receive::v2::{
    Initialized, PayjoinProposal, Receiver, ReceiverBuilder, UncheckedOriginalPayload,
};
use payjoin::ImplementationError;

use crate::{input_pair_from, Error, FeeRange, Step};

/// Wallet capabilities required by [`ReceiverSession`].
///
/// Implementors expose the four wallet-aware decisions the receiver makes:
/// SPK ownership, broadcast suitability of the sender's original transaction,
/// candidate inputs to contribute, and signing of the proposal PSBT. The runtime
/// drives everything else — typestate transitions, polling, the 5-stage check
/// ceremony, finalization.
pub trait ReceiverWallet {
    /// Is the given script-pubkey owned by this wallet?
    ///
    /// Called by both `check_inputs_not_owned` (to refuse a proposal where the
    /// sender claims to spend our outputs) and `identify_receiver_outputs` (to
    /// claim outputs the proposal pays us).
    fn is_owned(&self, spk: &Script) -> bool;

    /// Decide whether the sender's original transaction would be accepted by mempool
    /// policy. Typically a `testmempoolaccept` RPC call.
    fn check_broadcast(&self, tx: &Transaction) -> Result<bool, ImplementationError>;

    /// Produce the candidate inputs the receiver may contribute to the payjoin.
    ///
    /// The runtime will hand them to payjoin's `try_preserving_privacy` to pick
    /// one in a privacy-preserving manner. Build the candidates however you like
    /// (e.g. `Wallet::all_candidates().filter(...)` today, or via
    /// `bdk_chain::CanonicalView` once that lands).
    fn contribute(&self) -> Result<InputCandidates, Error>;

    /// Look up the spending plan for an outpoint we own. Used during proposal
    /// finalization to know how to satisfy each contributed input.
    fn plan_of_output(&self, op: OutPoint) -> Option<Plan>;

    /// Sign the PSBT in place. The runtime handles finalization separately, so
    /// implementors only need to add signatures.
    fn sign(&self, psbt: &mut Psbt) -> Result<(), Error>;

    /// Sequence to apply to contributed inputs whose plan does not pin one.
    /// Defaults to [`Sequence::ENABLE_RBF_NO_LOCKTIME`] (BIP-125 RBF, no locktime).
    fn fallback_sequence(&self) -> Sequence {
        Sequence::ENABLE_RBF_NO_LOCKTIME
    }
}

/// Sans-IO state machine for the payjoin v2 receiver role.
///
/// Drive by alternating [`poll`](Self::poll) (gives you a [`Step`] — what to do
/// next) and [`feed_response`](Self::feed_response) (consume the directory's
/// reply). The session terminates with `Step::Done` after publishing the
/// payjoin proposal back to the directory.
pub struct ReceiverSession<W> {
    wallet: W,
    fee_range: FeeRange,
    ohttp_relay: String,
    pj_uri: String,
    state: Option<State>,
}

// Variants have naturally different sizes (an `Initialized` session is much smaller
// than a fully-constructed `PayjoinProposal`), and at most one variant is ever
// stored at once, so boxing each variant gains nothing.
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
    /// Terminal failure. The optional `Error` is reported once via the next
    /// `poll` call and then replaced with `None` (subsequent calls report
    /// [`Error::Terminated`]).
    Failed(Option<Error>),
}

impl<W: ReceiverWallet> ReceiverSession<W> {
    /// Build a new session.
    ///
    /// The `builder` is already configured with the receiver's address, the
    /// directory URL, and the OHTTP keys; we just finalize it. `ohttp_relay` is
    /// the OHTTP CONNECT proxy through which every request is encapsulated.
    pub fn new(
        builder: ReceiverBuilder,
        ohttp_relay: impl Into<String>,
        wallet: W,
        fee_range: FeeRange,
    ) -> Result<Self, Error> {
        let persister = NoopSessionPersister::default();
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
        })
    }

    /// The BIP-21 / BIP-77 URI the receiver should share with the sender out of band.
    pub fn pj_uri(&self) -> &str {
        &self.pj_uri
    }

    /// Consume the session and return the wallet adapter.
    ///
    /// Useful for recovering ownership of the wallet after the session terminates
    /// (e.g. to sync against the broadcast transaction).
    pub fn into_wallet(self) -> W {
        self.wallet
    }

    /// Advance the state machine and report what the caller should do next.
    pub fn poll(&mut self) -> Step {
        let state = match self.state.take() {
            Some(s) => s,
            None => return Step::Failed(Error::Terminated),
        };
        let (next, step) = self.step(state);
        self.state = Some(next);
        step
    }

    /// Feed back the body of the directory response from the most recent
    /// `Step::SendRequest`. After this returns the caller should call `poll`
    /// again.
    pub fn feed_response(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let state = self.state.take().ok_or(Error::Terminated)?;
        let next = self.consume(state, bytes);
        self.state = Some(next);
        Ok(())
    }

    fn step(&self, state: State) -> (State, Step) {
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
                let persister = NoopSessionPersister::default();
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
        let persister = NoopSessionPersister::default();
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

        let candidates = wallet.contribute()?;
        let fb_seq = wallet.fallback_sequence();
        let inputs: Vec<_> = candidates
            .inputs()
            .filter_map(|i| input_pair_from(i, fb_seq))
            .collect();
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
                let f = Finalizer::from_psbt(&psbt, |op| wallet.plan_of_output(op));
                f.update_psbt(&mut psbt);
                wallet
                    .sign(&mut psbt)
                    .map_err(|e| ImplementationError::from(e.to_string().as_str()))?;
                // `finalize` here only resolves the receiver's contributed inputs; the
                // sender's inputs remain unfinalized on purpose and will be signed by
                // the sender after the proposal round-trips. `is_finalized()` would be
                // false at this point, but that's expected — don't treat it as an error.
                let _ = f.finalize(&mut psbt);
                Ok(psbt)
            })
            .save(&persister)
            .map_err(Error::payjoin)?;

        Ok(p)
    }
}
