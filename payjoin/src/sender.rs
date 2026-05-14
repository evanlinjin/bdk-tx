//! Sender-side high-level runtime.

use bdk_tx::Finalizer;
use bitcoin::{Amount, FeeRate, OutPoint, Psbt, Transaction, Txid};
use miniscript::plan::Plan;
use payjoin::persist::{NoopSessionPersister, OptionalTransitionOutcome};
use payjoin::send::v2::{PollingForProposal, Sender, SenderBuilder, WithReplyKey};
use payjoin::PjUri;

use crate::{psbt::restore_psbt_utxos, Error, Step};

/// Wallet capabilities required by [`SenderSession`].
///
/// The sender's only wallet-aware operations are looking up our own inputs in
/// the proposal PSBT and signing them. The runtime owns the rest of the flow.
pub trait SenderWallet {
    /// Look up the spending plan for an outpoint we own. Used to drive
    /// finalization on the proposal PSBT.
    fn plan_of_output(&self, op: OutPoint) -> Option<Plan>;

    /// Look up a previous transaction we have on hand. Used to restore the
    /// `non_witness_utxo` / `witness_utxo` fields that the payjoin proposal
    /// sanitizes away.
    fn prev_tx(&self, txid: Txid) -> Option<Transaction>;

    /// Sign the PSBT in place. The runtime handles finalization and extraction.
    fn sign(&self, psbt: &mut Psbt) -> Result<(), Error>;
}

/// Sans-IO state machine for the payjoin v2 sender role.
///
/// Drive by alternating [`poll`](Self::poll) and
/// [`feed_response`](Self::feed_response). When the session reaches
/// `Step::Done`, the broadcastable transaction is available via
/// [`final_tx`](Self::final_tx) and the network fee via [`fee`](Self::fee).
pub struct SenderSession<W> {
    wallet: W,
    ohttp_relay: String,
    state: Option<State>,
    result: Option<(Transaction, Amount)>,
}

// See the note on `receiver::State`. Sender state variants similarly vary in size
// (`PostingOriginal` vs. `Done`) but only one exists at a time.
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
    /// Terminal failure. See [`crate::receiver`] for the optional-error convention.
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
        let persister = NoopSessionPersister::default();
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
        })
    }

    /// The broadcastable transaction, once the session has reached `Step::Done`.
    pub fn final_tx(&self) -> Option<&Transaction> {
        self.result.as_ref().map(|(t, _)| t)
    }

    /// The network fee, once the session has reached `Step::Done`.
    pub fn fee(&self) -> Option<Amount> {
        self.result.as_ref().map(|(_, f)| *f)
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
    /// `Step::SendRequest`.
    pub fn feed_response(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let state = self.state.take().ok_or(Error::Terminated)?;
        let next = self.consume(state, bytes);
        self.state = Some(next);
        Ok(())
    }

    fn step(&self, state: State) -> (State, Step) {
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
                let persister = NoopSessionPersister::default();
                match session.process_response(&bytes, ctx).save(&persister) {
                    Ok(next) => State::PollingProposal {
                        session: next,
                        pending_backoff: false,
                    },
                    Err(e) => State::Failed(Some(Error::payjoin(e))),
                }
            }
            State::AwaitingProposalPoll { session, ctx } => {
                let persister = NoopSessionPersister::default();
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
        restore_psbt_utxos(
            &mut psbt,
            |op| self.wallet.plan_of_output(op),
            |txid| self.wallet.prev_tx(txid),
        );
        let f = Finalizer::from_psbt(&psbt, |op| self.wallet.plan_of_output(op));
        f.update_psbt(&mut psbt);
        self.wallet.sign(&mut psbt)?;
        if !f.finalize(&mut psbt).is_finalized() {
            return Err(Error::FinalizeFailed);
        }
        let tx = psbt.extract_tx().map_err(Error::payjoin)?;
        Ok((tx, fee))
    }
}
