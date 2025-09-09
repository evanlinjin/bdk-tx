use core::fmt::Debug;

use crate::{Input, Output, ScriptSource, Selection};
use alloc::vec::Vec;
use bdk_coin_select::{Candidate, CoinSelector, DrainWeights, TargetOutputs};
use miniscript::bitcoin::{Amount, FeeRate, TxOut, Weight};

/// Parameters for creating a Child-Pays-For-Parent (CPFP) transaction.
///
/// # Assumptions
///
/// This struct assumes the caller has constructed it correctly with:
/// - `package_fee` accurately represents the total fees paid by all parent transactions
/// - `package_weight` accurately represents the total weight of all parent transactions
/// - `inputs` that reference valid, spendable UTXO
/// - `target_package_feerate` is set to a value higher than the current effective
///   package feerate (package_fee / package_weight) to make the CPFP effective
/// - `output_script` that produces a valid output script
///
/// Violating these assumptions may result in errors during selection or invalid transactions.
#[derive(Debug, Clone)]
pub struct CpfpParams {
    /// Total fee paid by all transactions in the package.
    pub package_fee: Amount,
    /// Total weight of all transactions in the package.
    pub package_weight: Weight,
    /// Inputs that must be included in the CPFP transaction.
    pub inputs: Vec<Input>,
    /// Target feerate for the proposed package (including CPFP transaction).
    pub target_package_feerate: FeeRate,
    /// CPFP transaction output script.
    pub output_script: ScriptSource,
}

impl CpfpParams {
    /// Convert the CPFP parameters into selection.
    ///
    /// This method calculates the required child transaction fee to achieve the
    /// target package feerate and creates a selection with the appropriate inputs
    /// and outputs.
    pub fn into_selection(self) -> Result<Selection, CpfpError> {
        if self.inputs.is_empty() {
            return Err(CpfpError::InsufficientInputValue);
        }

        let mut child_output = TxOut {
            value: Amount::ZERO,
            script_pubkey: self.output_script.script(),
        };

        // Calculate child tx weight using `bdk_coin_select`.
        let child_weight = {
            let candidates = self
                .inputs
                .iter()
                .map(|input| {
                    Candidate::new(
                        input.prev_txout().value.to_sat(),
                        input.satisfaction_weight(),
                        input.is_segwit(),
                    )
                })
                .collect::<Vec<_>>();
            let mut selector = CoinSelector::new(&candidates);
            selector.select_all();
            selector.weight(
                TargetOutputs {
                    value_sum: 0,
                    weight_sum: child_output.weight().to_wu(),
                    n_outputs: 1,
                },
                DrainWeights::NONE,
            )
        };

        // Calculate the child fee needed to satisfy `target_package_feerate`.
        let child_fee = (self.target_package_feerate
            * (self.package_weight + Weight::from_wu(child_weight)))
        .checked_sub(self.package_fee)
        .ok_or(CpfpError::InsufficientInputValue)?;

        child_output.value = self
            .inputs
            .iter()
            .map(|input| input.prev_txout().value)
            .fold(Amount::ZERO, |acc, a| acc + a)
            .checked_sub(child_fee)
            .ok_or(CpfpError::InsufficientInputValue)?;

        if child_output.value < child_output.script_pubkey.minimal_non_dust() {
            return Err(CpfpError::OutputBelowDustLimit);
        }

        Ok(Selection {
            inputs: self.inputs,
            outputs: vec![Output::new(self.output_script, child_output.value)],
        })
    }
}

/// CPFP errors.
#[derive(Debug)]
pub enum CpfpError {
    /// Output value is below the dust threshold.
    OutputBelowDustLimit,
    /// Total input value is insufficient.
    InsufficientInputValue,
}

impl core::fmt::Display for CpfpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutputBelowDustLimit => write!(f, "output value is below dust threshold"),
            Self::InsufficientInputValue => {
                write!(f, "input value insufficient to cover required fee")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CpfpError {}
