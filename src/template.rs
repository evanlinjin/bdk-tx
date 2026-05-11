use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};

use miniscript::bitcoin;
use miniscript::bitcoin::{absolute, transaction, Psbt, Sequence};
use miniscript::psbt::PsbtExt;

use crate::{Finalizer, Input, Output, Selection};

/// Default sequence used for plan-based inputs that don't specify their own.
///
/// Matches Bitcoin Core's wallet default (`MAX_BIP125_RBF_SEQUENCE = 0xfffffffd`):
/// BIP125-signaling and lock_time-respecting.
pub const FALLBACK_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// Parameters for resolving a [`Selection`] into a [`TxTemplate`].
///
/// Carries only the *floors* and *defaults* that must be resolved at
/// template construction. Optional transformations (anti-fee-sniping,
/// shuffling, etc.) are exposed as methods on [`TxTemplate`].
#[derive(Debug, Clone)]
pub struct TemplateParams {
    /// Minimum tx version. Acts as a floor on `tx.version`:
    /// [`Selection::into_template`] bumps it to `Version::TWO` if any input
    /// requires CSV (BIP112), and [`TxTemplate::apply_anti_fee_sniping`]
    /// bumps it to `Version::TWO` when it picks the sequence branch.
    ///
    /// Default: [`transaction::Version::TWO`].
    pub min_version: transaction::Version,

    /// Minimum tx lock_time. Acts as a floor on `tx.lock_time`: the value
    /// used when no input requires an absolute locktime, or when all
    /// same-unit input CLTVs are below it. A different-unit fallback is
    /// ignored.
    ///
    /// Default: [`absolute::LockTime::ZERO`].
    pub min_locktime: absolute::LockTime,

    /// Default sequence used for plan-based inputs that don't specify their
    /// own (via plan-required relative timelock or via
    /// [`Input::set_sequence`]).
    ///
    /// Default: [`FALLBACK_SEQUENCE`] (Bitcoin Core's wallet default).
    pub fallback_sequence: Sequence,
}

impl Default for TemplateParams {
    fn default() -> Self {
        Self {
            min_version: transaction::Version::TWO,
            min_locktime: absolute::LockTime::ZERO,
            fallback_sequence: FALLBACK_SEQUENCE,
        }
    }
}

/// Parameters for building a [`Psbt`] from a [`TxTemplate`].
#[derive(Debug, Clone)]
pub struct PsbtBuildParams {
    /// Whether to require the full tx (PSBT [`non_witness_utxo`]) for
    /// segwit v0 inputs.
    ///
    /// Default: `true`.
    ///
    /// [`non_witness_utxo`]: bitcoin::psbt::Input::non_witness_utxo
    pub mandate_full_tx_for_segwit_v0: bool,
}

impl Default for PsbtBuildParams {
    fn default() -> Self {
        Self {
            mandate_full_tx_for_segwit_v0: true,
        }
    }
}

/// A fully-resolved tx shape, intermediate between [`Selection`] and the
/// final [`Psbt`] / [`bitcoin::Transaction`].
///
/// All floors and defaults from [`TemplateParams`] have been resolved into
/// concrete values: `version` and `lock_time` are the actual tx-level
/// values, and each input's sequence has been set (either by the input's
/// own plan requirement, an explicit override, or the fallback). Per-input
/// sighash overrides remain on the [`Input`] itself.
///
/// Marked `#[non_exhaustive]` so external crates cannot bypass the
/// [`Selection::into_template`] resolution flow by struct-literal
/// construction.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TxTemplate {
    /// Resolved tx version.
    pub version: transaction::Version,
    /// Resolved tx lock_time.
    pub lock_time: absolute::LockTime,
    /// Inputs in the resulting tx. Each input's sequence is resolved
    /// (`input.sequence()` returns `Some(_)` for all).
    pub inputs: Vec<Input>,
    /// Outputs in the resulting tx.
    pub outputs: Vec<Output>,
}

impl Selection {
    /// Resolve this selection into a [`TxTemplate`].
    ///
    /// - `tx.version` is computed as
    ///   `max(params.min_version, V2-if-any-input-requires-CSV)`.
    /// - `tx.lock_time` is computed as the maximum of input-required
    ///   CLTVs and `params.min_locktime` (when units agree; a
    ///   different-unit fallback is ignored).
    /// - For each input, if it has no sequence set (no plan-required
    ///   relative timelock, no [`Input::set_sequence`] override), the
    ///   `params.fallback_sequence` is applied.
    pub fn into_template(self, params: TemplateParams) -> TxTemplate {
        let inputs_require_v2 = self
            .inputs
            .iter()
            .any(|input| input.relative_timelock().is_some());
        let version = if inputs_require_v2 {
            params.min_version.max(transaction::Version::TWO)
        } else {
            params.min_version
        };

        let lock_time = Selection::accumulate_max_locktime(
            self.inputs.iter().filter_map(|i| i.absolute_timelock()),
            params.min_locktime,
        );

        let inputs: Vec<Input> = self
            .inputs
            .into_iter()
            .map(|mut input| {
                if input.sequence().is_none() {
                    input
                        .set_sequence(params.fallback_sequence)
                        .expect("input without relative_timelock accepts any sequence");
                }
                input
            })
            .collect();

        TxTemplate {
            version,
            lock_time,
            inputs,
            outputs: self.outputs,
        }
    }
}

/// Occurs when building a PSBT from a [`TxTemplate`] fails.
#[derive(Debug)]
pub enum CreatePsbtError {
    /// Missing full tx for a legacy input.
    MissingFullTxForLegacyInput(Box<Input>),
    /// Missing full tx for a segwit v0 input.
    MissingFullTxForSegwitV0Input(Box<Input>),
    /// PSBT construction error.
    Psbt(bitcoin::psbt::Error),
    /// PSBT output update error.
    OutputUpdate(miniscript::psbt::OutputUpdateError),
}

impl fmt::Display for CreatePsbtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreatePsbtError::MissingFullTxForLegacyInput(input) => write!(
                f,
                "legacy input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            CreatePsbtError::MissingFullTxForSegwitV0Input(input) => write!(
                f,
                "segwit v0 input that spends {} requires PSBT_IN_NON_WITNESS_UTXO",
                input.prev_outpoint()
            ),
            CreatePsbtError::Psbt(err) => Display::fmt(err, f),
            CreatePsbtError::OutputUpdate(err) => Display::fmt(err, f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreatePsbtError {}

impl TxTemplate {
    fn build_unsigned_tx(&self) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self
                .inputs
                .iter()
                .map(|input| bitcoin::TxIn {
                    previous_output: input.prev_outpoint(),
                    sequence: input
                        .sequence()
                        .expect("TxTemplate resolves every input's sequence"),
                    ..Default::default()
                })
                .collect(),
            output: self.outputs.iter().map(|output| output.txout()).collect(),
        }
    }

    /// Build the raw unsigned [`bitcoin::Transaction`] from this template.
    ///
    /// Useful for callers that don't need PSBT envelope semantics
    /// (signature management, witness fields, etc.) and just want the
    /// underlying tx structure.
    pub fn into_tx(self) -> bitcoin::Transaction {
        self.build_unsigned_tx()
    }

    /// Build a [`Psbt`] from this template (non-consuming).
    ///
    /// Doesn't consume `self`, so the template remains available for e.g.
    /// [`TxTemplate::into_finalizer`] afterward.
    pub fn create_psbt(&self, params: PsbtBuildParams) -> Result<Psbt, CreatePsbtError> {
        let tx = self.build_unsigned_tx();
        let mut psbt = Psbt::from_unsigned_tx(tx).map_err(CreatePsbtError::Psbt)?;

        for (plan_input, psbt_input) in self.inputs.iter().zip(psbt.inputs.iter_mut()) {
            if let Some(finalized_psbt_input) = plan_input.psbt_input() {
                *psbt_input = finalized_psbt_input.clone();
                continue;
            }
            if let Some(plan) = plan_input.plan() {
                plan.update_psbt_input(psbt_input);

                let witness_version = plan.witness_version();
                if witness_version.is_some() {
                    psbt_input.witness_utxo = Some(plan_input.prev_txout().clone());
                }
                psbt_input.non_witness_utxo = plan_input.prev_tx().cloned();
                if psbt_input.non_witness_utxo.is_none() {
                    if witness_version.is_none() {
                        return Err(CreatePsbtError::MissingFullTxForLegacyInput(Box::new(
                            plan_input.clone(),
                        )));
                    }
                    if params.mandate_full_tx_for_segwit_v0
                        && witness_version == Some(bitcoin::WitnessVersion::V0)
                    {
                        return Err(CreatePsbtError::MissingFullTxForSegwitV0Input(Box::new(
                            plan_input.clone(),
                        )));
                    }
                }

                psbt_input.sighash_type = plan_input.sighash_type();
                continue;
            }
            unreachable!("input candidate must either have finalized psbt input or plan");
        }

        for (output_index, output) in self.outputs.iter().enumerate() {
            if let Some(desc) = output.descriptor() {
                psbt.update_output_with_descriptor(output_index, desc)
                    .map_err(CreatePsbtError::OutputUpdate)?;
            }
        }

        Ok(psbt)
    }

    /// Into psbt [`Finalizer`].
    pub fn into_finalizer(self) -> Finalizer {
        Finalizer::new(
            self.inputs
                .iter()
                .filter_map(|input| Some((input.prev_outpoint(), input.plan().cloned()?))),
        )
    }
}
