use crate::Input;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};
use miniscript::bitcoin::{
    absolute::{self, LockTime},
    transaction::Version,
    Sequence, Transaction,
};
use rand_core::RngCore;

/// Errors that can occur while applying [`apply_anti_fee_sniping`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiFeeSnipingError {
    /// Transaction `version` is below 2; BIP326 requires version >= 2.
    UnsupportedVersion(Version),
    /// The transaction's existing `lock_time` is time-based (Unix timestamp),
    /// which is incompatible with BIP326's height-based AFS. The caller should
    /// either remove the time-based lock_time before calling, or skip AFS for
    /// this transaction.
    TimeBasedLocktime(LockTime),
    /// The transaction's existing `lock_time` is at a block height above the
    /// supplied `tip`. Applying AFS at the tip would lower `lock_time` below
    /// an input-required CLTV. Use a `tip_height` >= the existing locktime.
    TipBelowExistingLocktime {
        /// The transaction's current `lock_time` height.
        existing: absolute::Height,
        /// The supplied tip height.
        tip: absolute::Height,
    },
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
            AntiFeeSnipingError::TipBelowExistingLocktime { existing, tip } => write!(
                f,
                "tip height {} is below the transaction's existing lock_time {}",
                tip.to_consensus_u32(),
                existing.to_consensus_u32(),
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AntiFeeSnipingError {}

/// Applies BIP326 anti-fee-sniping (AFS) protection to a transaction.
///
/// AFS makes transaction-replay fee-sniping less profitable by signaling that
/// the transaction is fresh. The function chooses one of two approaches:
///
/// - **nLockTime**: sets `tx.lock_time` to approximately `tip_height`.
/// - **nSequence**: sets a randomly chosen Taproot input's `sequence` to
///   approximately its confirmation depth.
///
/// A 10% chance applies a small 0..100 random offset to either signal, to
/// avoid creating a unique fingerprint.
///
/// # Behavior contract
///
/// - The transaction's `version` must be >= 2.
/// - The transaction's existing `lock_time` must be either zero or a block
///   height at or below `tip_height`. Time-based existing lock_times are
///   rejected; existing heights above the tip are rejected.
/// - If the existing `lock_time` is non-zero (i.e. some input required a
///   CLTV), the locktime branch is forced and the written value is clamped
///   to `>= existing_height`. The sequence branch never runs in that case
///   (it would zero `tx.lock_time` and erase the input-required CLTV).
/// - `rbf_enabled` is derived from `tx.is_explicitly_rbf()` internally.
///
/// # Precondition
///
/// The caller must invoke this **before any signing**. Both `lock_time` and
/// the rewritten taproot input's `sequence` are part of the BIP143/BIP341
/// sighashes, so applying AFS after a partial sig has been added would
/// silently invalidate that sig.
///
/// # See Also
/// [BIP326](https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki)
pub fn apply_anti_fee_sniping(
    tx: &mut Transaction,
    inputs: &[Input],
    tip_height: absolute::Height,
    rng: &mut impl RngCore,
) -> Result<(), AntiFeeSnipingError> {
    const MAX_RELATIVE_HEIGHT: u32 = 65_535;
    const FIFTY_PERCENT_PROBABILITY_RANGE: u32 = 2;
    const MIN_SEQUENCE_VALUE: u32 = 1;
    const TEN_PERCENT_PROBABILITY_RANGE: u32 = 10;
    const MAX_RANDOM_OFFSET: u32 = 100;

    if tx.version < Version::TWO {
        return Err(AntiFeeSnipingError::UnsupportedVersion(tx.version));
    }

    // Validate the existing tx.lock_time against tip_height.
    let existing_height = match tx.lock_time {
        LockTime::Blocks(h) => {
            if h > tip_height {
                return Err(AntiFeeSnipingError::TipBelowExistingLocktime {
                    existing: h,
                    tip: tip_height,
                });
            }
            h
        }
        LockTime::Seconds(_) => {
            return Err(AntiFeeSnipingError::TimeBasedLocktime(tx.lock_time));
        }
    };

    let rbf_enabled = tx.is_explicitly_rbf();

    let taproot_inputs: Vec<(usize, &Input)> = tx
        .input
        .iter()
        .enumerate()
        .filter_map(|(vin, txin)| {
            let input = inputs
                .iter()
                .find(|input| input.prev_outpoint() == txin.previous_output)?;
            if input.prev_txout().script_pubkey.is_p2tr() {
                Some((vin, input))
            } else {
                None
            }
        })
        .collect();

    // The sequence branch zeroes tx.lock_time, which would erase any
    // input-required CLTV. Force the locktime branch when existing > 0.
    let preserve_existing_locktime = existing_height.to_consensus_u32() > 0;

    let must_use_locktime = preserve_existing_locktime
        || inputs.iter().any(|input| {
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

        // Never write below the existing locktime — preserves input-required CLTV.
        locktime = locktime.max(existing_height.to_consensus_u32());

        tx.lock_time = LockTime::from_height(locktime).expect("must be valid Height");
    } else {
        // existing_height is 0 here (otherwise must_use_locktime is true), so
        // this assignment is a no-op preserving BIP326 spec wording.
        tx.lock_time = LockTime::ZERO;
        let random_index = random_range(rng, taproot_inputs.len() as u32);
        let (input_index, input) = taproot_inputs[random_index as usize];
        let confirmation = input.confirmations(tip_height);

        let mut sequence_value = confirmation;
        if random_probability(rng, TEN_PERCENT_PROBABILITY_RANGE) {
            let random_offset = random_range(rng, MAX_RANDOM_OFFSET);
            sequence_value = sequence_value
                .saturating_sub(random_offset)
                .max(MIN_SEQUENCE_VALUE);
        }

        tx.input[input_index].sequence = Sequence(sequence_value);
    }

    Ok(())
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
            let selection = Selection {
                inputs: vec![input.clone()],
                outputs: vec![output],
            };
            let psbt = selection
                .create_psbt(PsbtParams {
                    fallback_locktime: LockTime::ZERO,
                    fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                })
                .unwrap();
            let psbt = selection
                .apply_anti_fee_sniping(psbt, tip_height, &mut OsRng)
                .unwrap();
            let tx = psbt.unsigned_tx;

            if tx.lock_time > LockTime::ZERO {
                used_locktime = true;
                let locktime_value = tx.lock_time.to_consensus_u32();
                let min_height = current_height.saturating_sub(100);
                assert!((min_height..=current_height).contains(&locktime_value));
                assert!(locktime_value <= current_height);
                assert!(locktime_value >= current_height.saturating_sub(100));
            } else {
                used_sequence = true;
                let sequence_value = tx.input[0].sequence.to_consensus_u32();
                let confirmations = input.confirmations(tip_height);

                let min_sequence = confirmations.saturating_sub(100);
                assert!((min_sequence..=confirmations).contains(&sequence_value));
                assert!(sequence_value >= 1, "Sequence must be at least 1");
                assert!(sequence_value <= confirmations);
                assert!(sequence_value >= confirmations.saturating_sub(100));
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
            let selection = Selection {
                inputs: vec![input1.clone(), input2.clone(), input3.clone()],
                outputs: vec![output.clone()],
            };
            let psbt = selection
                .create_psbt(PsbtParams {
                    fallback_locktime: LockTime::ZERO,
                    fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                })
                .unwrap();
            let psbt = selection
                .apply_anti_fee_sniping(psbt, tip_height, &mut OsRng)
                .unwrap();
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
        let confirmation_height = 800_000;
        let input = taproot_test_input(confirmation_height).unwrap();
        let inputs = vec![input];
        let tip_height = Height::from_consensus(confirmation_height + 50).unwrap();

        let mut tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: inputs[0].prev_outpoint(),
                ..Default::default()
            }],
            output: vec![],
        };

        let result = apply_anti_fee_sniping(&mut tx, &inputs, tip_height, &mut OsRng);
        assert!(matches!(
            result,
            Err(AntiFeeSnipingError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn test_anti_fee_sniping_time_based_locktime_error() {
        let input = taproot_test_input(800_000).unwrap();
        let inputs = vec![input];
        let tip_height = Height::from_consensus(800_050).unwrap();

        // A time-based existing lock_time is incompatible with BIP326.
        let time_locktime = LockTime::from_consensus(1_734_230_218);
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: time_locktime,
            input: vec![TxIn {
                previous_output: inputs[0].prev_outpoint(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            }],
            output: vec![],
        };

        let result = apply_anti_fee_sniping(&mut tx, &inputs, tip_height, &mut OsRng);
        assert!(
            matches!(result, Err(AntiFeeSnipingError::TimeBasedLocktime(lt)) if lt == time_locktime),
            "expected TimeBasedLocktime error, got {:?}",
            result
        );
    }

    #[test]
    fn test_anti_fee_sniping_tip_below_existing_error() {
        let input = taproot_test_input(800_000).unwrap();
        let inputs = vec![input];
        let tip_height = Height::from_consensus(800_050).unwrap();
        let existing = Height::from_consensus(800_060).unwrap();

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::Blocks(existing),
            input: vec![TxIn {
                previous_output: inputs[0].prev_outpoint(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..Default::default()
            }],
            output: vec![],
        };

        let result = apply_anti_fee_sniping(&mut tx, &inputs, tip_height, &mut OsRng);
        assert!(
            matches!(
                result,
                Err(AntiFeeSnipingError::TipBelowExistingLocktime { existing: e, tip: t })
                    if e == existing && t == tip_height
            ),
            "expected TipBelowExistingLocktime, got {:?}",
            result
        );
    }

    #[test]
    fn test_anti_fee_sniping_locktime_clamp_preserves_input_cltv() {
        // existing tx.lock_time is at exactly tip - 50: any random offset >= 50
        // would underflow it. Across many iterations, AFS must never write
        // below the existing locktime.
        let tip = 1_000_000u32;
        let existing = tip - 50;
        let confirmation_height = tip - 10;
        let input = taproot_test_input(confirmation_height).unwrap();
        let inputs = vec![input];
        let tip_height = Height::from_consensus(tip).unwrap();

        for _ in 0..200 {
            let mut tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::from_height(existing).unwrap(),
                input: vec![TxIn {
                    previous_output: inputs[0].prev_outpoint(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                }],
                output: vec![],
            };

            apply_anti_fee_sniping(&mut tx, &inputs, tip_height, &mut OsRng).unwrap();

            // Must always be locktime branch: existing > 0 forces it.
            assert!(tx.lock_time > LockTime::ZERO);
            assert!(
                tx.lock_time.to_consensus_u32() >= existing,
                "AFS wrote {} below existing CLTV {}",
                tx.lock_time.to_consensus_u32(),
                existing,
            );
            assert!(tx.lock_time.to_consensus_u32() <= tip);
        }
    }

    #[test]
    fn test_selection_apply_anti_fee_sniping_owned_in_owned_out() {
        // Smoke test: the wrapper takes a Psbt and returns a Psbt, mutating
        // either lock_time or a sequence value across iterations.
        let current_height = 2_500;
        let input = taproot_test_input(2_000).unwrap();
        let tip_height = Height::from_consensus(current_height).unwrap();

        let mut at_least_one_change = false;
        for _ in 0..10 {
            let selection = Selection {
                inputs: vec![input.clone()],
                outputs: vec![Output::with_script(
                    ScriptBuf::new(),
                    Amount::from_sat(9_000),
                )],
            };
            let psbt = selection
                .create_psbt(PsbtParams {
                    fallback_locktime: LockTime::ZERO,
                    fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                })
                .unwrap();
            let original_lt = psbt.unsigned_tx.lock_time;
            let original_seqs: Vec<u32> = psbt
                .unsigned_tx
                .input
                .iter()
                .map(|i| i.sequence.to_consensus_u32())
                .collect();

            let psbt = selection
                .apply_anti_fee_sniping(psbt, tip_height, &mut OsRng)
                .unwrap();

            let new_seqs: Vec<u32> = psbt
                .unsigned_tx
                .input
                .iter()
                .map(|i| i.sequence.to_consensus_u32())
                .collect();
            if psbt.unsigned_tx.lock_time != original_lt || new_seqs != original_seqs {
                at_least_one_change = true;
                break;
            }
        }
        assert!(at_least_one_change, "AFS should have mutated something");
    }
}
