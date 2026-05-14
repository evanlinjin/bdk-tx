//! Unit tests for the bdk_tx-flavored helpers in [`bdk_payjoin`].
//!
//! End-to-end behaviour of [`ReceiverSession`](bdk_payjoin::ReceiverSession) and
//! [`SenderSession`](bdk_payjoin::SenderSession) is covered by `examples/v2.rs`,
//! which talks to a live payjoin directory.

use bdk_payjoin::{input_pair_from, sign_and_finalize_with_plans};
use bdk_tx::Input;
use bitcoin::{
    absolute, key::Secp256k1, transaction, Amount, OutPoint, Psbt, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use miniscript::plan::Assets;
use miniscript::Descriptor;

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

const TR_XPRV: &str = "tr(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/86h/1h/0h/0/*)";
const WPKH_XPRV: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84h/1h/0h/0/*)";

fn make_input(descriptor: &str) -> Input {
    let secp = Secp256k1::new();
    let (desc, keymap) = Descriptor::parse_descriptor(&secp, descriptor).expect("descriptor");
    let def_desc = desc.at_derivation_index(0).expect("definite");
    let script_pubkey = def_desc.script_pubkey();

    let assets = keymap
        .keys()
        .fold(Assets::new(), |a, k| a.add(k.clone()));
    let plan = def_desc.plan(&assets).expect("plan");

    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            script_pubkey,
            value: Amount::from_sat(100_000),
        }],
    };
    let status = bdk_tx::ConfirmationStatus::new(1_000, Some(500_000_000)).expect("status");
    Input::from_prev_tx(plan, prev_tx, 0, Some(status)).expect("input")
}

// ---------------------------------------------------------------------------
// input_pair_from
// ---------------------------------------------------------------------------

#[test]
fn input_pair_from_p2tr_succeeds() {
    let input = make_input(TR_XPRV);
    let pair = input_pair_from(&input, Sequence::ENABLE_RBF_NO_LOCKTIME);
    assert!(
        pair.is_some(),
        "P2TR input should be accepted by InputPair::new \
         (explicit weight is passed by the helper)"
    );
}

#[test]
fn input_pair_from_p2wpkh_succeeds() {
    let input = make_input(WPKH_XPRV);
    let pair = input_pair_from(&input, Sequence::ENABLE_RBF_NO_LOCKTIME);
    assert!(
        pair.is_some(),
        "P2WPKH input should be accepted by InputPair::new \
         (payjoin can infer the weight, and the helper passes None for it)"
    );
}

#[test]
fn input_pair_from_propagates_sequence() {
    let input = make_input(WPKH_XPRV);
    let pair = input_pair_from(&input, Sequence(0x5555_5555)).expect("pair");
    let pair_dbg = format!("{pair:?}");
    assert!(
        pair_dbg.contains("5555"),
        "fallback sequence should be on the resulting TxIn, debug = {pair_dbg}"
    );
}

// ---------------------------------------------------------------------------
// sign_and_finalize_with_plans
// ---------------------------------------------------------------------------

fn empty_psbt() -> Psbt {
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![],
    };
    Psbt::from_unsigned_tx(tx).expect("psbt")
}

#[test]
fn sign_and_finalize_with_plans_invokes_signer() {
    let mut psbt = empty_psbt();
    let mut signer_called = false;
    let _ = sign_and_finalize_with_plans(
        &mut psbt,
        |_op| None, // no inputs are ours
        |_psbt| {
            signer_called = true;
            Ok(())
        },
    );
    assert!(signer_called, "signer closure should always run");
}

#[test]
fn sign_and_finalize_with_plans_propagates_signer_error() {
    let mut psbt = empty_psbt();
    let outcome = sign_and_finalize_with_plans(
        &mut psbt,
        |_op| None,
        |_psbt| Err(bdk_payjoin::Error::Wallet("test failure".into())),
    );
    match outcome {
        Err(bdk_payjoin::Error::Wallet(msg)) => assert_eq!(msg, "test failure"),
        other => panic!("expected signer error to propagate, got {other:?}"),
    }
}
