//! `bdk_tx` ergonomics for the [`payjoin_runtime`] sans-IO state machines.
//!
//! This crate re-exports the runtime and adds a small set of helpers that
//! convert `bdk_tx`-flavored values into the shapes the runtime traits expect:
//!
//! - [`input_pair_from`] / [`input_pairs_from`]: turn `bdk_tx::Input`s into
//!   payjoin [`InputPair`]s, handling the P2TR / P2WSH weight quirk.
//! - [`sign_and_finalize_with_plans`]: implement a wallet's `process_psbt`
//!   method using `bdk_tx::Finalizer` and a `plan_of_output` lookup.
//!
//! The runtime itself depends only on `payjoin`, `bitcoin`, and `bitcoin-ohttp`;
//! the `bdk_tx` integration is opt-in via this crate.
//!
//! ```ignore
//! use bdk_payjoin::{
//!     input_pairs_from, sign_and_finalize_with_plans, ReceiverSession, ReceiverWallet,
//! };
//! # struct MyWallet;
//! impl ReceiverWallet for MyWallet {
//!     // ... is_owned, check_broadcast ...
//!
//!     fn contribute(&self) -> Result<Vec<bdk_payjoin::InputPair>, bdk_payjoin::Error> {
//!         let candidates = todo!("build bdk_tx::InputCandidates");
//!         Ok(input_pairs_from(&candidates, bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME))
//!     }
//!
//!     fn process_psbt(&self, psbt: &mut bitcoin::Psbt) -> Result<(), bdk_payjoin::Error> {
//!         sign_and_finalize_with_plans(
//!             psbt,
//!             |op| todo!("look up plan for op"),
//!             |psbt| todo!("sign psbt with your signer"),
//!         )
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

/// Implement a wallet's `process_psbt` method using `bdk_tx::Finalizer` and a
/// per-outpoint plan lookup.
///
/// This is the typical adapter for both [`ReceiverWallet::process_psbt`] and
/// [`SenderWallet::process_psbt`]:
/// 1. Build a [`Finalizer`] for outpoints we own.
/// 2. Re-attach plan-derived fields (bip32 / taproot origins) to those PSBT
///    inputs.
/// 3. Call `sign` to add signatures.
/// 4. Finalize the inputs we own.
///
/// The `sign` closure is just `psbt.sign(&signer, &secp)` in most callers; we
/// don't take it directly so callers can pass their preferred error mapping.
///
/// For the **sender** call site, you'll typically pair this with
/// [`payjoin_runtime::restore_psbt_utxos`] before signing — the proposal often
/// strips `witness_utxo` / `non_witness_utxo` that the signer needs.
///
/// [`ReceiverWallet::process_psbt`]: payjoin_runtime::ReceiverWallet::process_psbt
/// [`SenderWallet::process_psbt`]: payjoin_runtime::SenderWallet::process_psbt
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
