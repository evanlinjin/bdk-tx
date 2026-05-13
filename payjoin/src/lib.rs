//! Glue between [`bdk_tx`] and the [`payjoin`] crate.
//!
//! This crate is a thin convenience layer — it encapsulates the conventions shared
//! by both libraries so callers don't have to discover them by hand. The functions
//! exposed here cover the receiver's contribute-inputs step (turning bdk_tx
//! candidate inputs into payjoin [`InputPair`]s).
//!
//! For the sender side of the v2 flow, no glue is needed: use
//! [`bdk_tx::Finalizer::from_psbt`] / [`bdk_tx::Finalizer::update_psbt`] to finalise
//! the sender's inputs in the proposal PSBT.
//!
//! # Example (receiver)
//!
//! ```ignore
//! # use bdk_tx::InputCandidates;
//! # use bitcoin::Sequence;
//! # fn contribute(payjoin: &payjoin::receive::v2::Receiver<payjoin::receive::v2::WantsInputs>,
//! #               candidates: &InputCandidates) -> anyhow::Result<()> {
//! let inputs = bdk_payjoin::input_pairs_from(candidates, Sequence::ENABLE_RBF_NO_LOCKTIME);
//! let selected = payjoin.try_preserving_privacy(inputs)?;
//! // pass `selected` (or a wider Vec) to `contribute_inputs`...
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

use bdk_tx::{Input, InputCandidates};
use bitcoin::Sequence;
use payjoin::receive::InputPair;

/// Convert a single [`Input`] into a payjoin [`InputPair`].
///
/// Handles the P2TR / P2WSH weight quirk: [`InputPair::new`] cannot infer the
/// witness weight for an unsigned taproot or witness-script-hash input, so we
/// pass the explicit weight derived from the input's spending plan. For input
/// types it *can* infer (P2WPKH, P2PKH, nested P2SH-P2WPKH) we pass `None`
/// because passing `Some` would be rejected as `ProvidedUnnecessaryWeight`.
///
/// `fallback_sequence` is used when the input's plan does not pin a specific
/// sequence (e.g. no relative timelock). Pass
/// [`Sequence::ENABLE_RBF_NO_LOCKTIME`] for the conventional payjoin case.
///
/// Returns `None` if payjoin rejects the input (e.g. the script type is
/// unsupported, the prev_tx / witness_utxo are missing, etc.).
pub fn input_pair_from(input: &Input, fallback_sequence: Sequence) -> Option<InputPair> {
    let spk = &input.prev_txout().script_pubkey;
    let needs_explicit_weight = spk.is_p2tr() || spk.is_p2wsh();
    let expected_weight = needs_explicit_weight.then(|| input.expected_input_weight());
    let (txin, psbt_input) = input.to_psbt_pair(fallback_sequence);
    InputPair::new(txin, psbt_input, expected_weight).ok()
}

/// Convert every input in `candidates` into a payjoin [`InputPair`].
///
/// Inputs that payjoin rejects are silently dropped. Pass the result to
/// `Receiver<WantsInputs>::try_preserving_privacy` or
/// `Receiver<WantsInputs>::contribute_inputs`.
pub fn input_pairs_from(
    candidates: &InputCandidates,
    fallback_sequence: Sequence,
) -> Vec<InputPair> {
    candidates
        .inputs()
        .filter_map(|input| input_pair_from(input, fallback_sequence))
        .collect()
}
