//! Unit tests for [`payjoin_runtime::restore_psbt_utxos`].

use bitcoin::{
    absolute, transaction, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

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

#[test]
fn restore_psbt_utxos_populates_owned_inputs() {
    let prev_tx = dummy_prev_tx(50_000);
    let mut psbt = psbt_spending(&prev_tx);
    let txid = prev_tx.compute_txid();
    assert!(psbt.inputs[0].witness_utxo.is_none());
    assert!(psbt.inputs[0].non_witness_utxo.is_none());

    payjoin_runtime::restore_psbt_utxos(
        &mut psbt,
        |_op| true,
        |t| (t == txid).then(|| prev_tx.clone()),
    );

    assert!(psbt.inputs[0].witness_utxo.is_some());
    assert_eq!(psbt.inputs[0].non_witness_utxo.as_ref(), Some(&prev_tx));
}

#[test]
fn restore_psbt_utxos_leaves_non_owned_inputs_untouched() {
    let prev_tx = dummy_prev_tx(50_000);
    let mut psbt = psbt_spending(&prev_tx);

    payjoin_runtime::restore_psbt_utxos(
        &mut psbt,
        |_op| false,
        |_| Some(prev_tx.clone()),
    );

    assert!(psbt.inputs[0].witness_utxo.is_none());
    assert!(psbt.inputs[0].non_witness_utxo.is_none());
}

#[test]
fn restore_psbt_utxos_skips_finalized_inputs() {
    let prev_tx = dummy_prev_tx(50_000);
    let mut psbt = psbt_spending(&prev_tx);
    psbt.inputs[0].final_script_sig = Some(ScriptBuf::from(vec![0x01]));

    payjoin_runtime::restore_psbt_utxos(&mut psbt, |_| true, |_| Some(prev_tx.clone()));

    assert!(psbt.inputs[0].witness_utxo.is_none());
    assert!(psbt.inputs[0].non_witness_utxo.is_none());
}
