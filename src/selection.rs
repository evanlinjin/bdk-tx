use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{Debug, Display};

use miniscript::bitcoin;
use miniscript::bitcoin::{absolute, transaction, Psbt, Sequence};
use miniscript::psbt::PsbtExt;

use crate::{Finalizer, Input, Output};

/// Default sequence value used for plan-based inputs that don't specify their own.
///
/// Matches Bitcoin Core's wallet default (`MAX_BIP125_RBF_SEQUENCE = 0xfffffffd`):
/// BIP125-signaling and lock_time-respecting. With Bitcoin Core 28+ defaulting
/// to Full RBF, the BIP125 signal is no longer load-bearing for replaceability,
/// but signaling explicitly is what virtually every modern wallet does and what
/// downstream tooling (block explorers, fee-bumping UIs) gates on.
const FALLBACK_SEQUENCE: bitcoin::Sequence = bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME;

/// Final selection of inputs and outputs.
///
/// Marked `#[non_exhaustive]` so external crates cannot bypass the structural
/// validation performed by [`Selector::new`] (notably the locktime-unit
/// consistency check). All publicly-reachable code paths that produce a
/// `Selection` route through [`Selector`], so downstream stages
/// ([`Selection::create_psbt`], [`Selection::apply_anti_fee_sniping`]) can
/// rely on those invariants.
///
/// [`Selector`]: crate::Selector
/// [`Selector::new`]: crate::Selector::new
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Selection {
    /// Inputs in this selection.
    pub inputs: Vec<Input>,
    /// Outputs in this selection.
    pub outputs: Vec<Output>,
}

/// Parameters for creating a psbt.
#[derive(Debug, Clone)]
pub struct PsbtParams {
    /// Use a specific [`transaction::Version`].
    pub version: transaction::Version,

    /// Minimum tx locktime.
    ///
    /// Acts as a floor on `tx.lock_time`: the value used when no input
    /// specifies a required absolute locktime, or when all input-required
    /// CLTVs (of the same unit as this field) are below it. A different-unit
    /// fallback is ignored so that e.g. a height-based default does not
    /// conflict with a time-based CLTV requirement.
    ///
    /// Default: [`absolute::LockTime::ZERO`]. Also the channel through which
    /// [`Selection::apply_anti_fee_sniping`] writes its locktime signal.
    pub min_locktime: absolute::LockTime,

    /// [`Sequence`] value to use by default if not provided by the input.
    ///
    /// Defaults to [`Sequence::ENABLE_RBF_NO_LOCKTIME`] (0xfffffffd) to match
    /// Bitcoin Core's wallet default (`MAX_BIP125_RBF_SEQUENCE`): BIP125-
    /// signaling, lock_time-respecting. This is what callers almost always
    /// want in 2026.
    pub fallback_sequence: Sequence,

    /// Whether to require the full tx, aka [`non_witness_utxo`] for segwit v0 inputs,
    /// default is `true`.
    ///
    /// [`non_witness_utxo`]: bitcoin::psbt::Input::non_witness_utxo
    pub mandate_full_tx_for_segwit_v0: bool,

    /// Sighash type to be used for each input.
    ///
    /// This option only applies to [`Input`]s that include a plan, as otherwise the given PSBT
    /// input can be expected to set a specific sighash type. Defaults to `None` which will not
    /// set an explicit sighash type for any input. (In that case the sighash will typically
    /// cover all of the outputs).
    pub sighash_type: Option<bitcoin::psbt::PsbtSighashType>,
}

impl Default for PsbtParams {
    fn default() -> Self {
        Self {
            version: transaction::Version::TWO,
            min_locktime: absolute::LockTime::ZERO,
            fallback_sequence: FALLBACK_SEQUENCE,
            mandate_full_tx_for_segwit_v0: true,
            sighash_type: None,
        }
    }
}

/// Occurs when creating a psbt fails.
#[derive(Debug)]
pub enum CreatePsbtError {
    /// Missing tx for legacy input.
    MissingFullTxForLegacyInput(Box<Input>),
    /// Missing tx for segwit v0 input.
    MissingFullTxForSegwitV0Input(Box<Input>),
    /// Psbt error.
    Psbt(bitcoin::psbt::Error),
    /// Update psbt output with descriptor error.
    OutputUpdate(miniscript::psbt::OutputUpdateError),
}

impl core::fmt::Display for CreatePsbtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
            CreatePsbtError::Psbt(error) => Display::fmt(&error, f),
            CreatePsbtError::OutputUpdate(output_update_error) => {
                Display::fmt(&output_update_error, f)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreatePsbtError {}

impl Selection {
    /// Accumulates the maximum locktime from an iterator of input-required locktimes.
    ///
    /// Returns the `min_locktime` if the locktimes iterator is empty, or the maximum
    /// locktime if all items share the same unit. A different-unit fallback is intentionally
    /// ignored so that e.g. a height-based fallback does not conflict with a time-based CLTV
    /// requirement.
    ///
    /// # Panics
    ///
    /// Debug-panics if the iterator yields locktimes of mixed units. This invariant is
    /// enforced upstream by [`Selector::new`][sel]; reaching this panic means a `Selection`
    /// was constructed by some path that bypassed validation.
    ///
    /// [sel]: crate::Selector::new
    pub(crate) fn accumulate_max_locktime(
        locktimes: impl IntoIterator<Item = absolute::LockTime>,
        min_locktime: absolute::LockTime,
    ) -> absolute::LockTime {
        let mut acc = Option::<absolute::LockTime>::None;
        for locktime in locktimes {
            match &mut acc {
                Some(existing) => {
                    debug_assert!(
                        existing.is_same_unit(locktime),
                        "Selector::new should have rejected mixed locktime units"
                    );
                    if existing.is_implied_by(locktime) {
                        *existing = locktime;
                    }
                }
                acc => *acc = Some(locktime),
            };
        }
        match acc {
            // No required locktimes from inputs: use fallback directly.
            None => min_locktime,
            // Same unit as fallback: take the maximum of required and fallback.
            Some(lock_time) if lock_time.is_same_unit(min_locktime) => {
                if lock_time.is_implied_by(min_locktime) {
                    min_locktime
                } else {
                    lock_time
                }
            }
            // Fallback is a different unit: use required locktime and ignore fallback.
            Some(lock_time) => lock_time,
        }
    }

    /// Create PSBT.
    pub fn create_psbt(&self, params: PsbtParams) -> Result<bitcoin::Psbt, CreatePsbtError> {
        let tx = bitcoin::Transaction {
            version: params.version,
            lock_time: Self::accumulate_max_locktime(
                self.inputs
                    .iter()
                    .filter_map(|input| input.absolute_timelock()),
                params.min_locktime,
            ),
            input: self
                .inputs
                .iter()
                .map(|input| bitcoin::TxIn {
                    previous_output: input.prev_outpoint(),
                    sequence: input.sequence().unwrap_or(params.fallback_sequence),
                    ..Default::default()
                })
                .collect(),
            output: self.outputs.iter().map(|output| output.txout()).collect(),
        };

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
                // We are allowed to have full tx for segwit inputs. Might as well include it.
                // If the caller does not wish to include the full tx in Segwit V0 inputs, they should not
                // include it in `crate::Input`.
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

                psbt_input.sighash_type = params.sighash_type;

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

    /// Into psbt finalizer.
    pub fn into_finalizer(self) -> Finalizer {
        Finalizer::new(
            self.inputs
                .iter()
                .filter_map(|input| Some((input.prev_outpoint(), input.plan().cloned()?))),
        )
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::{self, LockTime},
        secp256k1::Secp256k1,
        transaction, Amount, ScriptBuf, Transaction, TxIn, TxOut,
    };
    use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};

    #[test]
    fn test_min_locktime_height() -> anyhow::Result<()> {
        let abs_locktime = absolute::LockTime::from_consensus(100_000);
        let secp = Secp256k1::new();
        let pk = "032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3";
        let desc_str = format!("wsh(and_v(v:pk({pk}),after({abs_locktime})))");
        let desc_pk: DescriptorPublicKey = pk.parse()?;
        let (desc, _) = Descriptor::parse_descriptor(&secp, &desc_str)?;
        let plan = desc
            .at_derivation_index(0)?
            .plan(&Assets::new().add(desc_pk).after(abs_locktime))
            .unwrap();

        let prev_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey: desc.at_derivation_index(0)?.script_pubkey(),
                value: Amount::ONE_BTC,
            }],
        };
        let input = Input::from_prev_tx(plan, prev_tx, 0, None)?;

        let selection = Selection {
            inputs: vec![input],
            outputs: vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        };

        struct TestCase {
            name: &'static str,
            psbt_params: PsbtParams,
            exp_locktime: u32,
        }

        let cases = vec![
            TestCase {
                name: "no fallback locktime, use plan locktime",
                psbt_params: PsbtParams::default(),
                exp_locktime: 100_000,
            },
            TestCase {
                name: "larger fallback locktime is used",
                psbt_params: PsbtParams {
                    min_locktime: absolute::LockTime::from_consensus(100_100),
                    ..Default::default()
                },
                exp_locktime: 100_100,
            },
            TestCase {
                name: "smaller fallback locktime is ignored",
                psbt_params: PsbtParams {
                    min_locktime: absolute::LockTime::from_consensus(99_900),
                    ..Default::default()
                },
                exp_locktime: 100_000,
            },
        ];

        for test in cases {
            let psbt = selection.create_psbt(test.psbt_params)?;
            assert_eq!(
                psbt.unsigned_tx.lock_time.to_consensus_u32(),
                test.exp_locktime,
                "Test failed {}",
                test.name,
            );
        }

        Ok(())
    }

    /// Tests that a height-based fallback locktime is ignored when the input
    /// requires a time-based (UNIX timestamp) CLTV, and that an explicit time-based
    /// fallback greater than the requirement is respected.
    #[test]
    fn test_min_locktime_respects_lock_type() -> anyhow::Result<()> {
        let time_locktime = absolute::LockTime::from_consensus(1_734_230_218);
        let secp = Secp256k1::new();
        let pk = "032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3";
        let desc_str = format!("wsh(and_v(v:pk({pk}),after({time_locktime})))");
        let desc_pk: DescriptorPublicKey = pk.parse()?;
        let (desc, _) = Descriptor::parse_descriptor(&secp, &desc_str)?;
        let plan = desc
            .at_derivation_index(0)?
            .plan(&Assets::new().add(desc_pk).after(time_locktime))
            .unwrap();

        let prev_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey: desc.at_derivation_index(0)?.script_pubkey(),
                value: Amount::ONE_BTC,
            }],
        };
        let input = Input::from_prev_tx(plan, prev_tx, 0, None)?;

        let selection = Selection {
            inputs: vec![input],
            outputs: vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        };

        // Default fallback is height 0 (block-height unit). It is incompatible with the
        // time-based CLTV requirement, so it must be ignored.
        let psbt = selection.create_psbt(PsbtParams::default())?;
        assert_eq!(
            psbt.unsigned_tx.lock_time, time_locktime,
            "time-based CLTV requirement should be used; height-based fallback must be ignored",
        );

        // An explicit time-based fallback *greater* than the requirement should be respected.
        let larger_time = absolute::LockTime::from_consensus(1_772_167_108);
        assert!(larger_time > time_locktime);
        let psbt = selection.create_psbt(PsbtParams {
            min_locktime: larger_time,
            ..Default::default()
        })?;
        assert_eq!(
            psbt.unsigned_tx.lock_time, larger_time,
            "a larger time-based fallback should override the CLTV requirement",
        );

        Ok(())
    }

    #[test]
    fn test_create_psbt_does_not_apply_afs() -> anyhow::Result<()> {
        // `create_psbt` is now AFS-free: lock_time matches `min_locktime`
        // when no input requires a CLTV.
        let secp = Secp256k1::new();
        let desc =
            Descriptor::parse_descriptor(&secp, "tr([83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*)")
                .unwrap()
                .0;
        let def_desc = desc.at_derivation_index(0).unwrap();
        let script_pubkey = def_desc.script_pubkey();
        let desc_pk: DescriptorPublicKey =
            "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*"
                .parse()?;
        let assets = Assets::new().add(desc_pk);
        let plan = def_desc.plan(&assets).expect("failed to create plan");

        let prev_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey,
                value: Amount::from_sat(10_000),
            }],
        };
        let status = crate::ConfirmationStatus {
            height: absolute::Height::from_consensus(2_000)?,
            prev_mtp: Some(absolute::Time::from_consensus(500_000_000)?),
        };
        let input = Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;

        let current_height = 2_500;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection {
            inputs: vec![input],
            outputs: vec![output],
        };

        let psbt = selection.create_psbt(PsbtParams {
            min_locktime: LockTime::from_consensus(current_height),
            fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        })?;
        assert_eq!(
            psbt.unsigned_tx.lock_time.to_consensus_u32(),
            current_height
        );

        Ok(())
    }
}
