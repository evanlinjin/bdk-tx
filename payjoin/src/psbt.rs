//! PSBT helpers used by the runtime and exposed for callers driving payjoin manually.

use bitcoin::{OutPoint, Psbt, Transaction, Txid};
use miniscript::plan::Plan;

/// Restore `witness_utxo` and `non_witness_utxo` on PSBT inputs the caller owns.
///
/// Payjoin proposals (and many other counterparty-modified PSBTs) sanitize away
/// the prev-out information that signers need. Call this on a PSBT before signing
/// to put it back from your own UTXO source.
///
/// - `plan_for(op)` should return `Some(_)` exactly for outpoints the caller owns.
///   Inputs for which it returns `None` are left untouched.
/// - `prev_tx_of(txid)` looks up the transaction containing the outpoint. If it
///   returns `None`, the input is left as-is (the caller doesn't have the prev
///   tx on hand — that's fine, the signer may still cope via witness-only data).
///
/// Already-finalized inputs (those with `final_script_sig` or
/// `final_script_witness` populated) are always left untouched.
pub fn restore_psbt_utxos(
    psbt: &mut Psbt,
    plan_for: impl Fn(OutPoint) -> Option<Plan>,
    prev_tx_of: impl Fn(Txid) -> Option<Transaction>,
) {
    for input_index in 0..psbt.inputs.len() {
        let outpoint = psbt.unsigned_tx.input[input_index].previous_output;
        if plan_for(outpoint).is_none() {
            continue;
        }
        let psbt_input = &mut psbt.inputs[input_index];
        if psbt_input.final_script_witness.is_some() || psbt_input.final_script_sig.is_some() {
            continue;
        }
        if let Some(prev_tx) = prev_tx_of(outpoint.txid) {
            if let Some(txout) = prev_tx.output.get(outpoint.vout as usize) {
                psbt_input.witness_utxo = Some(txout.clone());
            }
            psbt_input.non_witness_utxo = Some(prev_tx);
        }
    }
}
