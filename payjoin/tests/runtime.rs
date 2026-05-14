//! Unit tests for the bdk_payjoin helpers.
//!
//! End-to-end behaviour of [`ReceiverSession`](bdk_payjoin::ReceiverSession) and
//! [`SenderSession`](bdk_payjoin::SenderSession) is covered by `examples/v2.rs`,
//! which talks to a live payjoin directory. Constructing those types in unit
//! tests would require an `OhttpKeys` value, which the upstream crate only
//! exposes a `FromStr` impl for under `#[cfg(test)]`. The tests here therefore
//! focus on the transport-independent helpers:
//!
//! - [`bdk_payjoin::input_pair_from`] and the P2TR / P2WSH weight quirk
//! - [`bdk_payjoin::restore_psbt_utxos`] and the "leave non-owned inputs alone"
//!   contract

use bdk_payjoin::{input_pair_from, restore_psbt_utxos};
use bdk_tx::Input;
use bitcoin::{
    absolute, key::Secp256k1, psbt, secp256k1, transaction, Amount, OutPoint, Psbt, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness,
};
use miniscript::plan::{Assets, Plan};
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
    // No relative timelock → plan.sequence() is None → fallback applies.
    let pair = input_pair_from(&input, Sequence(0x5555_5555)).expect("pair");
    let pair_dbg = format!("{pair:?}");
    assert!(
        pair_dbg.contains("5555"),
        "fallback sequence should be on the resulting TxIn, debug = {pair_dbg}"
    );
}

// ---------------------------------------------------------------------------
// restore_psbt_utxos
// ---------------------------------------------------------------------------

fn dummy_prev_tx(value_sat: u64) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn psbt_spending(prev_tx: &Transaction) -> Psbt {
    let txid = prev_tx.compute_txid();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![],
    };
    Psbt::from_unsigned_tx(tx).expect("psbt")
}

fn dummy_plan() -> Plan {
    let secp = Secp256k1::new();
    let (desc, keymap) = Descriptor::parse_descriptor(&secp, WPKH_XPRV).expect("descriptor");
    let def = desc.at_derivation_index(0).expect("definite");
    let assets = keymap.keys().fold(Assets::new(), |a, k| a.add(k.clone()));
    def.plan(&assets).expect("plan")
}

#[test]
fn restore_psbt_utxos_populates_owned_inputs() {
    let prev_tx = dummy_prev_tx(50_000);
    let mut psbt = psbt_spending(&prev_tx);
    let txid = prev_tx.compute_txid();
    assert!(psbt.inputs[0].witness_utxo.is_none());
    assert!(psbt.inputs[0].non_witness_utxo.is_none());

    let plan = dummy_plan();
    restore_psbt_utxos(
        &mut psbt,
        |_op| Some(plan.clone()),
        |t| (t == txid).then(|| prev_tx.clone()),
    );

    assert!(psbt.inputs[0].witness_utxo.is_some());
    assert_eq!(psbt.inputs[0].non_witness_utxo.as_ref(), Some(&prev_tx));
}

#[test]
fn restore_psbt_utxos_leaves_non_owned_inputs_untouched() {
    let prev_tx = dummy_prev_tx(50_000);
    let mut psbt = psbt_spending(&prev_tx);

    // Plan-lookup returns None → input is "not ours".
    restore_psbt_utxos(&mut psbt, |_| None, |_| Some(prev_tx.clone()));

    assert!(psbt.inputs[0].witness_utxo.is_none());
    assert!(psbt.inputs[0].non_witness_utxo.is_none());
}

#[test]
fn restore_psbt_utxos_skips_finalized_inputs() {
    let prev_tx = dummy_prev_tx(50_000);
    let mut psbt = psbt_spending(&prev_tx);
    psbt.inputs[0].final_script_sig = Some(ScriptBuf::from(vec![0x01]));

    let plan = dummy_plan();
    restore_psbt_utxos(
        &mut psbt,
        |_| Some(plan.clone()),
        |_| Some(prev_tx.clone()),
    );

    // Already finalized: should not have been touched.
    assert!(psbt.inputs[0].witness_utxo.is_none());
    assert!(psbt.inputs[0].non_witness_utxo.is_none());
}

// Silence unused-import warnings for items the fixture helpers happen not to use.
#[allow(dead_code)]
fn _force_use(_: psbt::Input, _: secp256k1::PublicKey) {}
