//! PSBT helpers exposed for callers driving payjoin manually.

use bitcoin::{OutPoint, Psbt, Transaction, Txid};

/// Restore `witness_utxo` and `non_witness_utxo` on PSBT inputs the caller owns.
///
/// Payjoin proposals (and many other counterparty-modified PSBTs) sanitize away
/// the prev-out information that signers need. Call this on a PSBT before
/// signing to put it back from your own UTXO source.
///
/// - `is_owned(op)` should return `true` exactly for outpoints the caller owns.
///   Inputs for which it returns `false` are left untouched.
/// - `get_tx(txid)` looks up the transaction with the given txid. If it returns
///   `None`, the input is left as-is.
///
/// Already-finalized inputs (those with `final_script_sig` or
/// `final_script_witness` populated) are always left untouched.
pub fn restore_psbt_utxos(
    psbt: &mut Psbt,
    is_owned: impl Fn(OutPoint) -> bool,
    get_tx: impl Fn(Txid) -> Option<Transaction>,
) {
    for input_index in 0..psbt.inputs.len() {
        let outpoint = psbt.unsigned_tx.input[input_index].previous_output;
        if !is_owned(outpoint) {
            continue;
        }
        let psbt_input = &mut psbt.inputs[input_index];
        if psbt_input.final_script_witness.is_some() || psbt_input.final_script_sig.is_some() {
            continue;
        }
        if let Some(prev_tx) = get_tx(outpoint.txid) {
            if let Some(txout) = prev_tx.output.get(outpoint.vout as usize) {
                psbt_input.witness_utxo = Some(txout.clone());
            }
            psbt_input.non_witness_utxo = Some(prev_tx);
        }
    }
}
