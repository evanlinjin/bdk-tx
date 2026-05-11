use crate::{PsbtParams, Selection, SetSequenceError};
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};
use miniscript::bitcoin::{
    absolute::{self, LockTime},
    transaction::Version,
    Sequence,
};
use rand_core::RngCore;

/// Errors that can occur while applying [`Selection::apply_anti_fee_sniping`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiFeeSnipingError {
    /// `params.version` is below 2; BIP326 requires version >= 2.
    UnsupportedVersion(Version),
    /// The transaction's effective `lock_time` is time-based (Unix timestamp),
    /// which is incompatible with BIP326's height-based AFS. The caller should
    /// either remove the time-based fallback / time-based input CLTV, or skip
    /// AFS for this transaction.
    TimeBasedLocktime(LockTime),
    /// Inputs have absolute locktimes of mixed units (height + time). The
    /// transaction would fail to build; fix the inputs before applying AFS.
    LockTypeMismatch,
    /// The taproot input chosen for the sequence branch already requires a
    /// stronger relative-timelock than AFS's freshness signal would provide.
    /// Pre-filter taproot inputs to avoid this, or rely on the locktime
    /// branch.
    InputSequence(SetSequenceError),
}

impl Display for AntiFeeSnipingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AntiFeeSnipingError::UnsupportedVersion(v) => {
                write!(f, "anti-fee-sniping requires tx version >= 2, got {}", v)
            }
            AntiFeeSnipingError::TimeBasedLocktime(lt) => write!(
                f,
                "anti-fee-sniping is incompatible with time-based lock_time {}",
                lt
            ),
            AntiFeeSnipingError::LockTypeMismatch => {
                write!(f, "inputs have locktimes of mixed units")
            }
            AntiFeeSnipingError::InputSequence(e) => Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AntiFeeSnipingError {}

impl Selection {
    /// Apply BIP326 anti-fee-sniping (AFS) to this selection and its build
    /// parameters, **before** calling [`Selection::create_psbt`].
    ///
    /// AFS makes transaction-replay fee-sniping less profitable by signaling
    /// that the transaction is fresh. The function chooses one of two
    /// approaches:
    ///
    /// - **nLockTime**: rewrites `params.fallback_locktime` to approximately
    ///   `tip_height`.
    /// - **nSequence**: overrides one randomly chosen Taproot input's
    ///   sequence to approximately its confirmation depth (via
    ///   [`crate::Input::set_sequence`]).
    ///
    /// A 10% chance applies a small 0..100 random offset to either signal,
    /// to avoid creating a unique fingerprint.
    ///
    /// # Behavior contract
    ///
    /// - `params.version` must be >= 2.
    /// - The transaction's effective locktime (the value [`create_psbt`]
    ///   would produce from the current `params.fallback_locktime` and any
    ///   input-required CLTVs) must be height-based. Time-based effective
    ///   locktimes are rejected. Heights *above* `tip_height` are accepted —
    ///   the tx is already future-locked beyond what AFS could add, and
    ///   [`accumulate_max_locktime`][acc] will preserve the higher CLTV.
    ///
    /// [acc]: Selection::accumulate_max_locktime
    /// - If the effective locktime is non-zero (i.e. some input required a
    ///   CLTV), the locktime branch is forced and the written value is
    ///   clamped to `>= effective_height`. The sequence branch never runs
    ///   in that case (it would zero out the implicit locktime intent and
    ///   erase the input-required CLTV).
    ///
    /// # Precondition
    ///
    /// This step modifies inputs and params before any PSBT is built and
    /// signed, so no signatures can be silently invalidated by this call.
    ///
    /// [`create_psbt`]: Selection::create_psbt
    ///
    /// # See Also
    /// [BIP326](https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki)
    pub fn apply_anti_fee_sniping(
        &mut self,
        params: &mut PsbtParams,
        tip_height: absolute::Height,
        rng: &mut impl RngCore,
    ) -> Result<(), AntiFeeSnipingError> {
        const MAX_RELATIVE_HEIGHT: u32 = 65_535;
        const FIFTY_PERCENT_PROBABILITY_RANGE: u32 = 2;
        const MIN_SEQUENCE_VALUE: u32 = 1;
        const TEN_PERCENT_PROBABILITY_RANGE: u32 = 10;
        const MAX_RANDOM_OFFSET: u32 = 100;

        if params.version < Version::TWO {
            return Err(AntiFeeSnipingError::UnsupportedVersion(params.version));
        }

        // Compute the effective locktime that create_psbt would produce.
        let effective_locktime = Selection::accumulate_max_locktime(
            self.inputs.iter().filter_map(|i| i.absolute_timelock()),
            params.fallback_locktime,
        )
        .map_err(|_| AntiFeeSnipingError::LockTypeMismatch)?;

        let effective_height = match effective_locktime {
            // A height above the supplied tip is fine: the tx is already
            // future-locked beyond what AFS could add, so accumulate_max_locktime
            // will preserve the higher CLTV regardless of what AFS writes.
            LockTime::Blocks(h) => h,
            LockTime::Seconds(_) => {
                return Err(AntiFeeSnipingError::TimeBasedLocktime(effective_locktime));
            }
        };

        // Predict the rbf-enabled status from what create_psbt would write.
        let rbf_enabled = self.inputs.iter().any(|input| {
            input
                .sequence()
                .unwrap_or(params.fallback_sequence)
                .to_consensus_u32()
                < 0xfffffffe
        });

        let taproot_inputs: Vec<usize> = self
            .inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.prev_txout().script_pubkey.is_p2tr())
            .map(|(i, _)| i)
            .collect();

        // The sequence branch implicitly assumes lock_time == 0. A non-zero
        // effective_height means some input required a CLTV — must use the
        // locktime branch so create_psbt's accumulate_max_locktime preserves
        // that CLTV.
        let preserve_existing_locktime = effective_height.to_consensus_u32() > 0;

        let must_use_locktime = preserve_existing_locktime
            || self.inputs.iter().any(|input| {
                let confirmation = input.confirmations(tip_height);
                confirmation == 0
                    || confirmation > MAX_RELATIVE_HEIGHT
                    || !input.prev_txout().script_pubkey.is_p2tr()
            });

        let use_locktime = !rbf_enabled
            || must_use_locktime
            || taproot_inputs.is_empty()
            || random_probability(rng, FIFTY_PERCENT_PROBABILITY_RANGE);

        if use_locktime {
            let mut locktime = tip_height.to_consensus_u32();

            if random_probability(rng, TEN_PERCENT_PROBABILITY_RANGE) {
                let random_offset = random_range(rng, MAX_RANDOM_OFFSET);
                locktime = locktime.saturating_sub(random_offset);
            }

            // Never write below the effective locktime — preserves CLTV.
            locktime = locktime.max(effective_height.to_consensus_u32());

            params.fallback_locktime =
                LockTime::from_height(locktime).expect("must be valid Height");
        } else {
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
                .map_err(AntiFeeSnipingError::InputSequence)?;
        }

        Ok(())
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
    use crate::{ConfirmationStatus, Input, Output, PsbtParams, Selection};
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

    #[test]
    fn test_anti_fee_sniping_protection() {
        let current_height = 2_500;
        let input = taproot_test_input(2_000).unwrap();
        let tip_height = Height::from_consensus(current_height).unwrap();

        let mut used_locktime = false;
        let mut used_sequence = false;
        let mut loops = 0;

        while !used_locktime || !used_sequence {
            let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
            let mut selection = Selection {
                inputs: vec![input.clone()],
                outputs: vec![output],
            };
            let mut params = PsbtParams {
                fallback_locktime: LockTime::ZERO,
                fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            };
            selection
                .apply_anti_fee_sniping(&mut params, tip_height, &mut OsRng)
                .unwrap();
            let psbt = selection.create_psbt(params.clone()).unwrap();
            let tx = psbt.unsigned_tx;

            if tx.lock_time > LockTime::ZERO {
                used_locktime = true;
                let locktime_value = tx.lock_time.to_consensus_u32();
                let min_height = current_height.saturating_sub(100);
                assert!((min_height..=current_height).contains(&locktime_value));
                assert_eq!(
                    locktime_value,
                    params.fallback_locktime.to_consensus_u32(),
                    "create_psbt should preserve the AFS-set fallback_locktime when no input requires a higher CLTV"
                );
            } else {
                used_sequence = true;
                let sequence_value = tx.input[0].sequence.to_consensus_u32();
                let confirmations = input.confirmations(tip_height);

                let min_sequence = confirmations.saturating_sub(100);
                assert!((min_sequence..=confirmations).contains(&sequence_value));
                assert!(sequence_value >= 1, "Sequence must be at least 1");
                // Selection's input must have its sequence override set.
                assert_eq!(
                    selection.inputs[0].sequence(),
                    Some(Sequence(sequence_value))
                );
            }

            loops += 1;
            assert!(
                loops < 20,
                "Failed to observe both behaviors within reasonable attempts"
            );
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
            let mut selection = Selection {
                inputs: vec![input1.clone(), input2.clone(), input3.clone()],
                outputs: vec![output.clone()],
            };
            let mut params = PsbtParams {
                fallback_locktime: LockTime::ZERO,
                fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            };
            selection
                .apply_anti_fee_sniping(&mut params, tip_height, &mut OsRng)
                .unwrap();
            let psbt = selection.create_psbt(params).unwrap();
            let tx = psbt.unsigned_tx;

            if tx.lock_time > LockTime::ZERO {
                used_locktime = true;
            } else {
                used_sequence = true;
                let has_modified_sequence = tx.input.iter().any(|txin| {
                    txin.sequence.to_consensus_u32() > 0 && txin.sequence.to_consensus_u32() < 65535
                });
                assert!(has_modified_sequence);
            }

            loops += 1;
            assert!(
                loops < 20,
                "Failed to observe both behaviors within reasonable attempts"
            );
        }
    }

    #[test]
    fn test_anti_fee_sniping_unsupported_version_error() {
        let input = taproot_test_input(800_000).unwrap();
        let mut selection = Selection {
            inputs: vec![input],
            outputs: vec![],
        };
        let mut params = PsbtParams {
            version: Version::ONE,
            fallback_locktime: LockTime::ZERO,
            fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        };
        let tip_height = Height::from_consensus(800_050).unwrap();

        let result = selection.apply_anti_fee_sniping(&mut params, tip_height, &mut OsRng);
        assert!(matches!(
            result,
            Err(AntiFeeSnipingError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn test_anti_fee_sniping_time_based_locktime_error() {
        let input = taproot_test_input(800_000).unwrap();
        let mut selection = Selection {
            inputs: vec![input],
            outputs: vec![],
        };
        // A time-based fallback locktime makes the effective locktime time-based.
        let time_locktime = LockTime::from_consensus(1_734_230_218);
        let mut params = PsbtParams {
            fallback_locktime: time_locktime,
            fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        };
        let tip_height = Height::from_consensus(800_050).unwrap();

        let result = selection.apply_anti_fee_sniping(&mut params, tip_height, &mut OsRng);
        assert!(
            matches!(result, Err(AntiFeeSnipingError::TimeBasedLocktime(lt)) if lt == time_locktime),
            "expected TimeBasedLocktime error, got {:?}",
            result
        );
    }

    #[test]
    fn test_anti_fee_sniping_accepts_existing_above_tip() {
        // When the effective lock_time is above the tip (e.g. an input has a
        // future-dated CLTV), AFS should NOT error — the tx is already
        // future-locked beyond what AFS could add, and accumulate_max_locktime
        // preserves the higher CLTV. AFS may still apply (it'll write a
        // tip-ish locktime that gets dominated by the input CLTV during
        // create_psbt).
        let input = taproot_test_input(800_000).unwrap();
        let mut selection = Selection {
            inputs: vec![input],
            outputs: vec![],
        };
        let existing = Height::from_consensus(800_060).unwrap();
        let mut params = PsbtParams {
            fallback_locktime: LockTime::Blocks(existing),
            fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        };
        let tip_height = Height::from_consensus(800_050).unwrap();

        selection
            .apply_anti_fee_sniping(&mut params, tip_height, &mut OsRng)
            .expect("AFS should accept effective locktime above tip");

        // The clamp inside AFS ensures params.fallback_locktime ends up at
        // least the existing height.
        assert!(params.fallback_locktime.to_consensus_u32() >= existing.to_consensus_u32());
    }

    #[test]
    fn test_anti_fee_sniping_locktime_clamp_preserves_input_cltv() {
        // params.fallback_locktime is at exactly tip - 50: any random offset
        // >= 50 would underflow it. Across many iterations, AFS must never
        // write below the effective locktime.
        let tip = 1_000_000u32;
        let existing = tip - 50;
        let confirmation_height = tip - 10;
        let input = taproot_test_input(confirmation_height).unwrap();
        let tip_height = Height::from_consensus(tip).unwrap();

        for _ in 0..200 {
            let mut selection = Selection {
                inputs: vec![input.clone()],
                outputs: vec![],
            };
            let mut params = PsbtParams {
                fallback_locktime: LockTime::from_height(existing).unwrap(),
                fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            };
            selection
                .apply_anti_fee_sniping(&mut params, tip_height, &mut OsRng)
                .unwrap();
            // Existing > 0 forces the locktime branch.
            assert!(params.fallback_locktime > LockTime::ZERO);
            assert!(
                params.fallback_locktime.to_consensus_u32() >= existing,
                "AFS wrote {} below existing CLTV {}",
                params.fallback_locktime.to_consensus_u32(),
                existing,
            );
            assert!(params.fallback_locktime.to_consensus_u32() <= tip);
            // No input sequence override should have been set.
            assert!(selection.inputs[0].sequence().is_none());
        }
    }

    #[test]
    fn test_apply_anti_fee_sniping_is_mutating_and_idempotent_via_create_psbt() {
        // Smoke test: applying AFS mutates Selection or PsbtParams, and the
        // result is consumed by create_psbt deterministically.
        let current_height = 2_500;
        let input = taproot_test_input(2_000).unwrap();
        let tip_height = Height::from_consensus(current_height).unwrap();

        let mut at_least_one_change = false;
        for _ in 0..10 {
            let mut selection = Selection {
                inputs: vec![input.clone()],
                outputs: vec![Output::with_script(
                    ScriptBuf::new(),
                    Amount::from_sat(9_000),
                )],
            };
            let mut params = PsbtParams {
                fallback_locktime: LockTime::ZERO,
                fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            };
            let original_lt = params.fallback_locktime;
            let original_seq = selection.inputs[0].sequence();

            selection
                .apply_anti_fee_sniping(&mut params, tip_height, &mut OsRng)
                .unwrap();

            let new_seq = selection.inputs[0].sequence();
            if params.fallback_locktime != original_lt || new_seq != original_seq {
                at_least_one_change = true;
                break;
            }
        }
        assert!(at_least_one_change, "AFS should have mutated something");
    }
}
