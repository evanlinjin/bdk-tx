//! `bdk_tx` ergonomics for the [`payjoin_runtime`] sans-IO state machines.
//!
//! This crate re-exports the runtime and adds a small set of helpers that
//! convert `bdk_tx`-flavored values into the shapes the runtime expects:
//!
//! - [`input_pair_from`] / [`input_pairs_from`]: turn `bdk_tx::Input`s into
//!   payjoin [`InputPair`]s, handling the P2TR / P2WSH weight quirk. Use this
//!   to build the response to a [`ReceiverStep::Contribute`].
//! - [`sign_and_finalize_with_plans`]: sign and finalize a PSBT using
//!   `bdk_tx::Finalizer` + a `plan_of_output` lookup. Use this to build the
//!   PSBT you hand to
//!   [`ReceiverSession::feed_signed_psbt`](payjoin_runtime::ReceiverSession::feed_signed_psbt)
//!   /
//!   [`SenderSession::feed_signed_psbt`](payjoin_runtime::SenderSession::feed_signed_psbt).
//!
//! The runtime itself depends only on `payjoin`, `bitcoin`, and `bitcoin-ohttp`;
//! the `bdk_tx` integration is opt-in via this crate.
//!
//! ```ignore
//! use bdk_payjoin::{
//!     input_pairs_from, sign_and_finalize_with_plans, ReceiverSession, ReceiverStep,
//! };
//!
//! let mut session = ReceiverSession::new(builder, relay, fee_range)?;
//! loop {
//!     match session.poll() {
//!         ReceiverStep::Contribute => {
//!             let candidates = todo!("build bdk_tx::InputCandidates");
//!             let inputs = input_pairs_from(&candidates, bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME);
//!             session.feed_contribute(inputs)?;
//!         }
//!         ReceiverStep::SignAndFinalize(mut psbt) => {
//!             sign_and_finalize_with_plans(
//!                 &mut psbt,
//!                 |op| todo!("look up plan for op"),
//!                 |psbt| todo!("sign psbt with your signer"),
//!             )?;
//!             session.feed_signed_psbt(psbt)?;
//!         }
//!         // ... other ReceiverStep variants ...
//!         _ => todo!(),
//!     }
//! }
//! ```

#![warn(missing_docs)]

pub use payjoin_runtime::*;

use bdk_tx::{Finalizer, Input, InputCandidates};
use bitcoin::{OutPoint, Psbt, Sequence};
use miniscript::plan::Plan;

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
///
/// [`InputPair`]: payjoin_runtime::InputPair
/// [`InputPair::new`]: payjoin_runtime::InputPair::new
pub fn input_pair_from(
    input: &Input,
    fallback_sequence: Sequence,
) -> Option<payjoin_runtime::InputPair> {
    let spk = &input.prev_txout().script_pubkey;
    let needs_explicit_weight = spk.is_p2tr() || spk.is_p2wsh();
    let expected_weight = needs_explicit_weight.then(|| input.expected_input_weight());
    let (txin, psbt_input) = input.to_psbt_pair(fallback_sequence);
    payjoin_runtime::InputPair::new(txin, psbt_input, expected_weight).ok()
}

/// Convert every input in `candidates` into a payjoin [`InputPair`].
///
/// Inputs that payjoin rejects are silently dropped.
///
/// [`InputPair`]: payjoin_runtime::InputPair
pub fn input_pairs_from(
    candidates: &InputCandidates,
    fallback_sequence: Sequence,
) -> Vec<payjoin_runtime::InputPair> {
    candidates
        .inputs()
        .filter_map(|input| input_pair_from(input, fallback_sequence))
        .collect()
}

/// Sign and finalize a payjoin PSBT using `bdk_tx::Finalizer` and a
/// per-outpoint plan lookup.
///
/// Use this to build the PSBT you hand to
/// [`ReceiverSession::feed_signed_psbt`] /
/// [`SenderSession::feed_signed_psbt`]. The function:
///
/// 1. Builds a [`Finalizer`] for outpoints we own (those `plan_for` returns
///    `Some` for).
/// 2. Re-attaches plan-derived fields (bip32 / taproot origins) to those PSBT
///    inputs.
/// 3. Calls `sign` to add signatures.
/// 4. Finalizes the inputs we own.
///
/// The `sign` closure is typically `psbt.sign(&signer, &secp)` in callers; we
/// don't take it directly so callers can pass their preferred error mapping.
///
/// [`ReceiverSession::feed_signed_psbt`]: payjoin_runtime::ReceiverSession::feed_signed_psbt
/// [`SenderSession::feed_signed_psbt`]: payjoin_runtime::SenderSession::feed_signed_psbt
pub fn sign_and_finalize_with_plans(
    psbt: &mut Psbt,
    plan_for: impl Fn(OutPoint) -> Option<Plan>,
    sign: impl FnOnce(&mut Psbt) -> Result<(), payjoin_runtime::Error>,
) -> Result<(), payjoin_runtime::Error> {
    let finalizer = Finalizer::from_psbt(psbt, plan_for);
    finalizer.update_psbt(psbt);
    sign(psbt)?;
    let _ = finalizer.finalize(psbt);
    Ok(())
}
