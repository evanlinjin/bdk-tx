use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};

use miniscript::bitcoin;
use miniscript::bitcoin::{absolute, transaction, Psbt, Sequence};
use miniscript::psbt::PsbtExt;
use rand_core::RngCore;

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
/// Marked `#[non_exhaustive]` with `pub(crate)` fields so external crates
/// can only obtain a `TxTemplate` via [`Selection::into_template`], and
/// can only mutate it through validated methods
/// ([`TxTemplate::apply_anti_fee_sniping`],
/// [`TxTemplate::shuffle_inputs`], [`TxTemplate::shuffle_outputs`]).
/// External callers read via the field accessors below.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TxTemplate {
    pub(crate) version: transaction::Version,
    pub(crate) lock_time: absolute::LockTime,
    pub(crate) inputs: Vec<Input>,
    pub(crate) outputs: Vec<Output>,
}

impl TxTemplate {
    /// Resolved tx version.
    pub fn version(&self) -> transaction::Version {
        self.version
    }

    /// Resolved tx lock_time.
    pub fn lock_time(&self) -> absolute::LockTime {
        self.lock_time
    }

    /// Inputs in the resulting tx. Each input's sequence is resolved
    /// (`input.sequence()` returns `Some(_)` for all).
    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    /// Outputs in the resulting tx.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }
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
    /// Doesn't consume `self`, so the template remains available for
    /// further use (e.g. [`TxTemplate::populate_finalizer`]).
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

    /// Populate a [`Finalizer`] with `(outpoint, plan)` pairs from this
    /// template's inputs, then return `self` so it can be chained into
    /// further construction (e.g. [`TxTemplate::create_psbt`]).
    ///
    /// Inputs without a `Plan` (i.e. `PsbtInput`-variant inputs) contribute
    /// nothing — they don't need a finalizer entry because their PSBT input
    /// already carries the satisfaction data.
    pub fn populate_finalizer(self, finalizer: &mut Finalizer) -> Self {
        for input in &self.inputs {
            if let Some(plan) = input.plan() {
                finalizer.insert(input.prev_outpoint(), plan.clone());
            }
        }
        self
    }

    /// Shuffle the inputs in place.
    ///
    /// Useful for privacy: the order in which a coin selector picks inputs
    /// can leak information about the wallet (selection algorithm, UTXO
    /// freshness, etc.). Bitcoin Core shuffles inputs by default; this
    /// library leaves the choice to the caller.
    pub fn shuffle_inputs(mut self, rng: &mut impl RngCore) -> Self {
        fisher_yates_shuffle(&mut self.inputs, rng);
        self
    }

    /// Shuffle the outputs in place.
    ///
    /// Useful for privacy: the position of the change output (typically
    /// last) is otherwise a strong heuristic for transaction analysis.
    /// Bitcoin Core shuffles outputs by default; this library leaves the
    /// choice to the caller.
    pub fn shuffle_outputs(mut self, rng: &mut impl RngCore) -> Self {
        fisher_yates_shuffle(&mut self.outputs, rng);
        self
    }
}

/// In-place Fisher–Yates shuffle using only [`RngCore`].
///
/// Uses rejection sampling for unbiased index selection. Allocation-free.
fn fisher_yates_shuffle<T>(slice: &mut [T], rng: &mut impl RngCore) {
    let len = slice.len();
    if len < 2 {
        return;
    }
    for i in (1..len).rev() {
        let j = random_range(rng, (i + 1) as u32) as usize;
        slice.swap(i, j);
    }
}

/// Returns a random value in `[0, n)` using rejection sampling (unbiased).
fn random_range(rng: &mut impl RngCore, n: u32) -> u32 {
    debug_assert!(n > 0);
    let threshold = n.wrapping_neg() % n;
    loop {
        let v = rng.next_u32();
        if v >= threshold {
            return v % n;
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_fisher_yates_preserves_multiset() {
        // Shuffling preserves the multiset of elements (length, contents).
        let mut v: Vec<u32> = (0..50).collect();
        let original = v.clone();
        fisher_yates_shuffle(&mut v, &mut OsRng);
        v.sort();
        assert_eq!(v, original);
    }

    #[test]
    fn test_fisher_yates_eventually_permutes() {
        // Across many iterations, shuffling produces at least one ordering
        // different from the input. (Probability of N iterations all being
        // identity for length 10 is (1/10!)^N — vanishing.)
        let mut at_least_one_change = false;
        for _ in 0..20 {
            let mut v: Vec<u32> = (0..10).collect();
            let original = v.clone();
            fisher_yates_shuffle(&mut v, &mut OsRng);
            if v != original {
                at_least_one_change = true;
                break;
            }
        }
        assert!(at_least_one_change);
    }

    #[test]
    fn test_fisher_yates_handles_trivial_lengths() {
        let mut empty: Vec<u32> = vec![];
        fisher_yates_shuffle(&mut empty, &mut OsRng);
        assert!(empty.is_empty());

        let mut single = vec![42u32];
        fisher_yates_shuffle(&mut single, &mut OsRng);
        assert_eq!(single, vec![42]);
    }
}
