use alloc::vec::Vec;

use miniscript::bitcoin::absolute;

use crate::{Input, Output};

/// Final selection of inputs and outputs.
///
/// Marked `#[non_exhaustive]` with `pub(crate)` fields so external crates
/// can only obtain a `Selection` via [`Selector`]'s validated path. All
/// publicly-reachable code paths that produce a `Selection` route through
/// [`Selector`], so downstream stages ([`Selection::into_template`],
/// [`crate::TxTemplate::create_psbt`]) can rely on those invariants.
///
/// External callers read via [`Selection::inputs`] and [`Selection::outputs`].
///
/// [`Selector`]: crate::Selector
/// [`Selector::new`]: crate::Selector::new
/// [`Selection::into_template`]: crate::Selection::into_template
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Selection {
    pub(crate) inputs: Vec<Input>,
    pub(crate) outputs: Vec<Output>,
}

impl Selection {
    /// Inputs in this selection.
    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    /// Outputs in this selection.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }
}

impl Selection {
    /// Accumulates the maximum locktime from an iterator of input-required locktimes.
    ///
    /// Returns the `min_locktime` if the locktimes iterator is empty, or the
    /// maximum locktime if all items share the same unit. A different-unit
    /// fallback is intentionally ignored so that e.g. a height-based fallback
    /// does not conflict with a time-based CLTV requirement.
    ///
    /// # Panics
    ///
    /// Debug-panics if the iterator yields locktimes of mixed units. This
    /// invariant is enforced upstream by [`Selector::new`][sel]; reaching
    /// this panic means a `Selection` was constructed by some path that
    /// bypassed validation.
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
            None => min_locktime,
            Some(lock_time) if lock_time.is_same_unit(min_locktime) => {
                if lock_time.is_implied_by(min_locktime) {
                    min_locktime
                } else {
                    lock_time
                }
            }
            Some(lock_time) => lock_time,
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PsbtBuildParams, TxTemplateParams};
    use bitcoin::{
        absolute::LockTime, secp256k1::Secp256k1, transaction, Amount, ScriptBuf, Transaction,
        TxIn, TxOut,
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

        struct TestCase {
            name: &'static str,
            params: TxTemplateParams,
            exp_locktime: u32,
        }

        let cases = vec![
            TestCase {
                name: "no fallback locktime, use plan locktime",
                params: TxTemplateParams::default(),
                exp_locktime: 100_000,
            },
            TestCase {
                name: "larger fallback locktime is used",
                params: TxTemplateParams {
                    min_locktime: absolute::LockTime::from_consensus(100_100),
                    ..Default::default()
                },
                exp_locktime: 100_100,
            },
            TestCase {
                name: "smaller fallback locktime is ignored",
                params: TxTemplateParams {
                    min_locktime: absolute::LockTime::from_consensus(99_900),
                    ..Default::default()
                },
                exp_locktime: 100_000,
            },
        ];

        for test in cases {
            let selection = Selection {
                inputs: vec![input.clone()],
                outputs: vec![Output::with_descriptor(
                    desc.at_derivation_index(1)?,
                    Amount::from_sat(1000),
                )],
            };
            let (psbt, _) = selection
                .into_template(test.params)
                .create_psbt(PsbtBuildParams::default())?;
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

        // Default fallback is height 0 (block-height unit). It is incompatible with the
        // time-based CLTV requirement, so it must be ignored.
        let selection = Selection {
            inputs: vec![input.clone()],
            outputs: vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        };
        let (psbt, _) = selection
            .into_template(TxTemplateParams::default())
            .create_psbt(PsbtBuildParams::default())?;
        assert_eq!(
            psbt.unsigned_tx.lock_time, time_locktime,
            "time-based CLTV requirement should be used; height-based fallback must be ignored",
        );

        // An explicit time-based fallback *greater* than the requirement should be respected.
        let larger_time = absolute::LockTime::from_consensus(1_772_167_108);
        assert!(larger_time > time_locktime);
        let selection = Selection {
            inputs: vec![input],
            outputs: vec![Output::with_descriptor(
                desc.at_derivation_index(1)?,
                Amount::from_sat(1000),
            )],
        };
        let (psbt, _) = selection
            .into_template(TxTemplateParams {
                min_locktime: larger_time,
                ..Default::default()
            })
            .create_psbt(PsbtBuildParams::default())?;
        assert_eq!(
            psbt.unsigned_tx.lock_time, larger_time,
            "a larger time-based fallback should override the CLTV requirement",
        );

        Ok(())
    }

    #[test]
    fn test_into_template_does_not_apply_afs() -> anyhow::Result<()> {
        // `into_template` is AFS-free: lock_time matches `min_locktime`
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

        let (psbt, _) = selection
            .into_template(TxTemplateParams {
                min_locktime: LockTime::from_consensus(current_height),
                ..Default::default()
            })
            .create_psbt(PsbtBuildParams::default())?;
        assert_eq!(
            psbt.unsigned_tx.lock_time.to_consensus_u32(),
            current_height
        );

        Ok(())
    }
}
