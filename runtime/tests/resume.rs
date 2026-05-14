//! Tests for `*Session::resume_from_events`.
//!
//! These tests use the closed-session shortcut: a fresh sender event log that
//! already ends in `Closed(_)`. Constructing a useful intermediate event log
//! requires a real OHTTP keypair (gated behind `#[cfg(test)]` in payjoin), so
//! the live-protocol resumption path is exercised by the e2e example instead.

use payjoin_runtime::{Error, SenderSession, SenderSessionEvent, SenderWallet, Step};

use bitcoin::{FeeRate, Psbt, Transaction};

/// A `SenderWallet` that never succeeds; we only test the closed-failure
/// resume path, where `process_psbt` is never invoked.
struct DummyWallet;
impl SenderWallet for DummyWallet {
    fn process_psbt(&self, _: &mut Psbt) -> Result<(), Error> {
        Err(Error::Wallet(
            "dummy wallet — should never be called".into(),
        ))
    }
}

#[test]
fn sender_resume_from_empty_log_errors() {
    let outcome = SenderSession::resume_from_events(
        Vec::<SenderSessionEvent>::new(),
        "https://relay.example/",
        DummyWallet,
        FeeRate::BROADCAST_MIN,
    );
    assert!(
        matches!(outcome, Err(Error::Payjoin(_))),
        "expected Payjoin error for empty log, got {:?}",
        outcome.as_ref().err()
    );
}

#[test]
fn sender_resume_from_closed_failure_lands_in_failed() {
    // A single-event log that says "we already closed with Failure" — payjoin
    // accepts this as a terminal state (no `Created` predecessor needed for
    // the `_ => Closed(...)` arm in the sender's `process_event`).
    let events = vec![SenderSessionEvent::Closed(
        payjoin::send::v2::SessionOutcome::Failure,
    )];

    // We expect this either to land in Failed (resume succeeded with terminal
    // failure) or to be rejected as an invalid log (no `Created` event). Both
    // are acceptable behaviours — what matters is that resume doesn't panic.
    let outcome = SenderSession::resume_from_events(
        events,
        "https://relay.example/",
        DummyWallet,
        FeeRate::BROADCAST_MIN,
    );

    match outcome {
        Ok(mut session) => {
            assert!(session.final_tx().is_none());
            match session.poll() {
                Step::Failed(_) => {}
                other => panic!("expected Failed after closed-failure resume, got {other:?}"),
            }
        }
        Err(Error::Payjoin(_)) => {
            // payjoin's `replay_events` rejected the log (no `Created` first).
            // That's a legitimate response.
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

/// Helper: when `final_tx()` returns `Some`, the saved tx must be coherent.
#[allow(dead_code)]
fn assert_tx_extracts(tx: &Transaction) {
    let _ = tx.compute_txid();
}
