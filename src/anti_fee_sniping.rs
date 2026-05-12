use crate::TxTemplate;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};
use miniscript::bitcoin::{
    absolute::{self, LockTime},
    transaction::Version,
    Sequence,
};
use rand_core::RngCore;

/// Errors that can occur while applying [`TxTemplate::apply_anti_fee_sniping`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiFeeSnipingError {
    /// AFS could not apply: the template's `lock_time` is time-based (which
    /// makes the locktime branch a no-op under BIP326's height-based
    /// semantics), and the sequence branch is also ineligible — one or
    /// more inputs are non-taproot, unconfirmed, or have more than
    /// `MAX_RELATIVE_HEIGHT` confirmations.
    ///
    /// Remedies: remove the time-based input CLTV / fallback, switch to
    /// taproot+confirmed inputs in an RBF-signaling tx, or skip AFS for
    /// this transaction.
    NoApplicableBranch(LockTime),
}

impl Display for AntiFeeSnipingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AntiFeeSnipingError::NoApplicableBranch(lt) => write!(
                f,
                "anti-fee-sniping cannot apply: time-based lock_time {} blocks the locktime branch and the sequence branch is ineligible",
                lt
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AntiFeeSnipingError {}

impl TxTemplate {
    /// Apply BIP326 anti-fee-sniping (AFS) to this template.
    ///
    /// AFS makes transaction-replay fee-sniping less profitable by signaling
    /// that the transaction is fresh. The function chooses one of two
    /// approaches:
    ///
    /// - **nLockTime**: rewrites `self.lock_time` to approximately
    ///   `tip_height` (clamped to the template's existing `lock_time`).
    /// - **nSequence**: overrides one randomly chosen taproot input's
    ///   sequence to approximately its confirmation depth, and bumps
    ///   `self.version` to [`Version::TWO`] if it was lower (BIP68
    ///   semantics require v2+).
    ///
    /// A 10% chance applies a small 0..100 random offset to either signal,
    /// to avoid creating a unique fingerprint.
    ///
    /// # Behavior contract
    ///
    /// - If `self.lock_time` is **time-based**, the locktime branch can't
    ///   apply (BIP326 is height-based). AFS forces the sequence branch.
    ///   If the sequence branch is also ineligible (non-taproot input,
    ///   unconfirmed input, RBF disabled, etc.), AFS returns
    ///   [`AntiFeeSnipingError::NoApplicableBranch`].
    /// - If `self.lock_time` is height-based and **non-zero**, the
    ///   locktime branch is forced (mixing both signals on the same tx is
    ///   non-spec under BIP326). The written value is clamped to
    ///   `>= self.lock_time`.
    /// - If `self.lock_time` is height-based and **above** `tip_height`,
    ///   the tx is already future-locked; AFS still runs, but the locktime
    ///   branch's write is clamped up to the existing value.
    ///
    /// # See Also
    /// [BIP326](https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki)
    pub fn apply_anti_fee_sniping(
        mut self,
        tip_height: absolute::Height,
        rng: &mut impl RngCore,
    ) -> Result<Self, AntiFeeSnipingError> {
        const MAX_RELATIVE_HEIGHT: u32 = 65_535;
        const FIFTY_PERCENT_PROBABILITY_RANGE: u32 = 2;
        const MIN_SEQUENCE_VALUE: u32 = 1;
        const TEN_PERCENT_PROBABILITY_RANGE: u32 = 10;
        const MAX_RANDOM_OFFSET: u32 = 100;

        // A time-based lock_time excludes the locktime branch (AFS writes
        // are height-based).
        let existing_height = match self.lock_time {
            LockTime::Blocks(h) => Some(h),
            LockTime::Seconds(_) => None,
        };

        let rbf_enabled = self.inputs.iter().any(|input| {
            input
                .sequence()
                .expect("TxTemplate resolves every input's sequence")
                .to_consensus_u32()
                < 0xfffffffe
        });

        // Taproot inputs are eligible for the sequence branch only if they
        // have no existing relative-timelock requirement: AFS's freshness
        // signal (~confirmation depth, possibly minus a random offset) could
        // otherwise be weaker than the input's required value.
        let taproot_inputs: Vec<usize> = self
            .inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| {
                input.prev_txout().script_pubkey.is_p2tr() && input.relative_timelock().is_none()
            })
            .map(|(i, _)| i)
            .collect();

        // Non-zero height-based lock_time means some input required a CLTV
        // — must use the locktime branch (mixing signals is non-spec).
        let preserve_existing_locktime = existing_height
            .map(|h| h.to_consensus_u32() > 0)
            .unwrap_or(false);

        let must_use_locktime = preserve_existing_locktime
            || self.inputs.iter().any(|input| {
                let confirmation = input.confirmations(tip_height);
                confirmation == 0
                    || confirmation > MAX_RELATIVE_HEIGHT
                    || !input.prev_txout().script_pubkey.is_p2tr()
            });

        // Time-based lock_time excludes the locktime branch.
        let must_use_sequence = existing_height.is_none();

        if must_use_locktime && must_use_sequence {
            return Err(AntiFeeSnipingError::NoApplicableBranch(self.lock_time));
        }

        let use_locktime = must_use_locktime
            || (!must_use_sequence
                && (!rbf_enabled
                    || taproot_inputs.is_empty()
                    || random_probability(rng, FIFTY_PERCENT_PROBABILITY_RANGE)));

        if use_locktime {
            let existing_height =
                existing_height.expect("locktime branch requires height-based lock_time");

            let mut locktime = tip_height.to_consensus_u32();
            if random_probability(rng, TEN_PERCENT_PROBABILITY_RANGE) {
                let random_offset = random_range(rng, MAX_RANDOM_OFFSET);
                locktime = locktime.saturating_sub(random_offset);
            }
            // Never write below the existing lock_time — preserves CLTV.
            locktime = locktime.max(existing_height.to_consensus_u32());

            self.lock_time = LockTime::from_height(locktime).expect("must be valid Height");
        } else {
            // Sequence branch needs BIP68 semantics: bump version to V2.
            self.version = self.version.max(Version::TWO);

            let random_index = random_range(rng, taproot_inputs.len() as u32);
            let input_index = taproot_inputs[random_index as usize];
            let confirmation = self.inputs[input_index].confirmations(tip_height);

            let mut sequence_value = confirmation;
            if random_probability(rng, TEN_PERCENT_PROBABILITY_RANGE) {
                let random_offset = random_range(rng, MAX_RANDOM_OFFSET);
                sequence_value = sequence_value
                    .saturating_sub(random_offset)
                    .max(MIN_SEQUENCE_VALUE);
            }

            self.inputs[input_index]
                .set_sequence(Sequence(sequence_value))
                .expect("taproot_inputs filtered to inputs without relative-timelock");
        }

        Ok(self)
    }
}

/// Returns true with probability 1/n.
fn random_probability(rng: &mut impl RngCore, n: u32) -> bool {
    random_range(rng, n) == 0
}

/// Returns a random value in the range [0, n) using rejection-sampling for
/// uniform distribution.
fn random_range(rng: &mut impl RngCore, n: u32) -> u32 {
    let threshold = n.wrapping_neg() % n;

    loop {
        let value = rng.next_u32();
        if value >= threshold {
            return value % n;
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfirmationStatus, Input, Output, Selection, TxTemplateParams};
    use bitcoin::{
        absolute::{Height, Time},
        secp256k1::Secp256k1,
        transaction::{self, Version},
        Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    };
    use miniscript::{plan::Assets, Descriptor, DescriptorPublicKey};
    use rand_core::OsRng;

    const TEST_DESCRIPTOR: &str = "tr([83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*)";
    const TEST_DESCRIPTOR_PK: &str = "[83737d5e/86h/1h/0h]tpubDDR5GgtoxS8fJyjjvdahN4VzV5DV6jtbcyvVXhEKq2XtpxjxBXmxH3r8QrNbQqHg4bJM1EGkxi7Pjfkgnui9jQWqS7kxHvX6rhUeriLDKxz/0/*";

    fn taproot_test_input(confirmation_height: u32) -> anyhow::Result<Input> {
        let secp = Secp256k1::new();
        let desc = Descriptor::parse_descriptor(&secp, TEST_DESCRIPTOR)
            .unwrap()
            .0;
        let def_desc = desc.at_derivation_index(0).unwrap();
        let script_pubkey = def_desc.script_pubkey();
        let desc_pk: DescriptorPublicKey = TEST_DESCRIPTOR_PK.parse()?;
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

        let status = ConfirmationStatus {
            height: Height::from_consensus(confirmation_height)?,
            prev_mtp: Some(Time::from_consensus(500_000_000)?),
        };

        Ok(Input::from_prev_tx(plan, prev_tx, 0, Some(status))?)
    }

    fn template_with_input(input: Input) -> TxTemplate {
        Selection {
            inputs: vec![input],
            outputs: vec![Output::with_script(
                ScriptBuf::new(),
                Amount::from_sat(9_000),
            )],
        }
        .into_template(TxTemplateParams::default())
    }

    #[test]
    fn test_anti_fee_sniping_protection() {
        let current_height = 2_500;
        let input = taproot_test_input(2_000).unwrap();
        let tip_height = Height::from_consensus(current_height).unwrap();

        let mut used_locktime = false;
        let mut used_sequence = false;
        let mut loops = 0;

        while !used_locktime || !used_sequence {
            let template = template_with_input(input.clone());
            let template = template
                .apply_anti_fee_sniping(tip_height, &mut OsRng)
                .unwrap();

            if template.lock_time > LockTime::ZERO {
                used_locktime = true;
                let locktime_value = template.lock_time.to_consensus_u32();
                let min_height = current_height.saturating_sub(100);
                assert!((min_height..=current_height).contains(&locktime_value));
            } else {
                used_sequence = true;
                let seq = template.inputs[0]
                    .sequence()
                    .expect("template resolves sequence");
                let sequence_value = seq.to_consensus_u32();
                let confirmations = input.confirmations(tip_height);

                let min_sequence = confirmations.saturating_sub(100);
                assert!((min_sequence..=confirmations).contains(&sequence_value));
                assert!(sequence_value >= 1, "Sequence must be at least 1");
                assert_eq!(template.version, Version::TWO);
            }

            loops += 1;
            assert!(loops < 20, "Failed to observe both behaviors");
        }
    }

    #[test]
    fn test_anti_fee_sniping_multiple_taproot_inputs() {
        let current_height = 3_000;
        let input1 = taproot_test_input(2_500).unwrap();
        let input2 = taproot_test_input(2_700).unwrap();
        let input3 = taproot_test_input(3_000).unwrap();
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(18_000));
        let tip_height = Height::from_consensus(current_height).unwrap();

        let mut used_locktime = false;
        let mut used_sequence = false;
        let mut loops = 0;

        while !used_locktime || !used_sequence {
            let template = Selection {
                inputs: vec![input1.clone(), input2.clone(), input3.clone()],
                outputs: vec![output.clone()],
            }
            .into_template(TxTemplateParams::default())
            .apply_anti_fee_sniping(tip_height, &mut OsRng)
            .unwrap();

            if template.lock_time > LockTime::ZERO {
                used_locktime = true;
            } else {
                used_sequence = true;
                let has_modified_sequence = template.inputs.iter().any(|input| {
                    let seq = input.sequence().expect("resolved").to_consensus_u32();
                    seq > 0 && seq < 65535
                });
                assert!(has_modified_sequence);
            }

            loops += 1;
            assert!(loops < 20, "Failed to observe both behaviors");
        }
    }

    #[test]
    fn test_anti_fee_sniping_accepts_existing_above_tip() {
        // When the template's lock_time is above the tip (e.g. an input has a
        // future-dated CLTV), AFS should NOT error — the tx is already
        // future-locked beyond what AFS could add.
        let input = taproot_test_input(800_000).unwrap();
        let existing = Height::from_consensus(800_060).unwrap();
        let tip_height = Height::from_consensus(800_050).unwrap();

        let template = Selection {
            inputs: vec![input],
            outputs: vec![],
        }
        .into_template(TxTemplateParams {
            min_locktime: LockTime::Blocks(existing),
            ..Default::default()
        });

        let template = template
            .apply_anti_fee_sniping(tip_height, &mut OsRng)
            .expect("AFS should accept lock_time above tip");

        assert!(template.lock_time.to_consensus_u32() >= existing.to_consensus_u32());
    }

    #[test]
    fn test_anti_fee_sniping_locktime_clamp_preserves_input_cltv() {
        let tip = 1_000_000u32;
        let existing = tip - 50;
        let confirmation_height = tip - 10;
        let input = taproot_test_input(confirmation_height).unwrap();
        let tip_height = Height::from_consensus(tip).unwrap();

        for _ in 0..200 {
            let template = Selection {
                inputs: vec![input.clone()],
                outputs: vec![],
            }
            .into_template(TxTemplateParams {
                min_locktime: LockTime::from_height(existing).unwrap(),
                ..Default::default()
            })
            .apply_anti_fee_sniping(tip_height, &mut OsRng)
            .unwrap();
            assert!(template.lock_time > LockTime::ZERO);
            assert!(
                template.lock_time.to_consensus_u32() >= existing,
                "AFS wrote {} below existing CLTV {}",
                template.lock_time.to_consensus_u32(),
                existing,
            );
            assert!(template.lock_time.to_consensus_u32() <= tip);
        }
    }

    #[test]
    fn test_anti_fee_sniping_time_based_locktime_forces_sequence_branch() {
        let input = taproot_test_input(800_000).unwrap();
        let time_locktime = LockTime::from_consensus(1_734_230_218);
        let tip_height = Height::from_consensus(800_050).unwrap();

        for _ in 0..50 {
            let template = Selection {
                inputs: vec![input.clone()],
                outputs: vec![],
            }
            .into_template(TxTemplateParams {
                min_locktime: time_locktime,
                ..Default::default()
            })
            .apply_anti_fee_sniping(tip_height, &mut OsRng)
            .expect("AFS should force sequence branch when lock_time is time-based");

            // Time-based lock_time must not be rewritten by AFS.
            assert_eq!(template.lock_time, time_locktime);
            assert_eq!(template.version, Version::TWO);
            let seq = template.inputs[0].sequence().expect("sequence must be set");
            assert!(seq.to_consensus_u32() >= 1);
            assert!(seq.to_consensus_u32() <= 51);
        }
    }

    #[test]
    fn test_anti_fee_sniping_no_applicable_branch() {
        // Time-based lock_time + non-taproot input → both branches infeasible.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pk = "032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3";
        let desc_pk: DescriptorPublicKey = pk.parse().unwrap();
        let (desc, _) = Descriptor::parse_descriptor(&secp, &format!("wpkh({pk})")).unwrap();
        let plan = desc
            .at_derivation_index(0)
            .unwrap()
            .plan(&Assets::new().add(desc_pk))
            .unwrap();
        let prev_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey: desc.at_derivation_index(0).unwrap().script_pubkey(),
                value: Amount::from_sat(10_000),
            }],
        };
        let status = ConfirmationStatus {
            height: Height::from_consensus(2_000).unwrap(),
            prev_mtp: Some(Time::from_consensus(500_000_000).unwrap()),
        };
        let input = Input::from_prev_tx(plan, prev_tx, 0, Some(status)).unwrap();

        let time_locktime = LockTime::from_consensus(1_734_230_218);
        let template = Selection {
            inputs: vec![input],
            outputs: vec![],
        }
        .into_template(TxTemplateParams {
            min_locktime: time_locktime,
            ..Default::default()
        });
        let tip_height = Height::from_consensus(2_500).unwrap();

        let result = template.apply_anti_fee_sniping(tip_height, &mut OsRng);
        assert!(
            matches!(result, Err(AntiFeeSnipingError::NoApplicableBranch(lt)) if lt == time_locktime),
            "expected NoApplicableBranch, got {:?}",
            result
        );
    }

    #[test]
    fn test_anti_fee_sniping_v1_min_version_is_bumped_opportunistically() {
        let input = taproot_test_input(800_000).unwrap();
        let tip_height = Height::from_consensus(800_050).unwrap();

        let mut saw_locktime_branch = false;
        let mut saw_sequence_branch = false;
        let mut loops = 0;
        while !saw_locktime_branch || !saw_sequence_branch {
            let template = Selection {
                inputs: vec![input.clone()],
                outputs: vec![Output::with_script(
                    ScriptBuf::new(),
                    Amount::from_sat(9_000),
                )],
            }
            .into_template(TxTemplateParams {
                min_version: Version::ONE,
                ..Default::default()
            })
            .apply_anti_fee_sniping(tip_height, &mut OsRng)
            .unwrap();

            if template.inputs[0]
                .sequence()
                .expect("resolved")
                .to_consensus_u32()
                < 0xfffffffe
                && template.lock_time == LockTime::ZERO
            {
                saw_sequence_branch = true;
                assert_eq!(template.version, Version::TWO);
            } else if template.lock_time > LockTime::ZERO {
                saw_locktime_branch = true;
                assert_eq!(template.version, Version::ONE);
            }

            loops += 1;
            assert!(loops < 30, "failed to observe both branches");
        }
    }

    #[test]
    fn test_anti_fee_sniping_skips_inputs_with_relative_timelock() -> anyhow::Result<()> {
        use bitcoin::hashes::Hash;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pubkey =
            bitcoin::key::XOnlyPublicKey::from_slice(&[2u8; 32]).expect("valid x-only pubkey");
        let p2tr_script = bitcoin::ScriptBuf::new_p2tr(&secp, pubkey, None);
        assert!(p2tr_script.is_p2tr());

        let older_sequence = Sequence::from_height(50);
        let psbt_input = bitcoin::psbt::Input {
            witness_utxo: Some(TxOut {
                script_pubkey: p2tr_script,
                value: Amount::from_sat(10_000),
            }),
            ..Default::default()
        };
        let outpoint = bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0);
        let status = ConfirmationStatus {
            height: Height::from_consensus(2_000)?,
            prev_mtp: Some(Time::from_consensus(500_000_000)?),
        };
        let input = Input::from_psbt_input(
            outpoint,
            older_sequence,
            psbt_input,
            64,
            Some(status),
            false,
        )?;

        let tip_height = Height::from_consensus(2_500).unwrap();
        for _ in 0..50 {
            let template = Selection {
                inputs: vec![input.clone()],
                outputs: vec![Output::with_script(
                    ScriptBuf::new(),
                    Amount::from_sat(9_000),
                )],
            }
            .into_template(TxTemplateParams::default())
            .apply_anti_fee_sniping(tip_height, &mut OsRng)
            .unwrap();
            assert!(
                template.lock_time > LockTime::ZERO,
                "AFS should have taken the locktime branch"
            );
            // The input's sequence must still encode the older() requirement.
            assert_eq!(template.inputs[0].sequence(), Some(older_sequence));
        }
        Ok(())
    }
}
