use crate::collections::{BTreeMap, HashMap};
use core::fmt;

use bitcoin::psbt::PsbtSighashType;
use bitcoin::{OutPoint, Psbt, Witness};
use miniscript::{bitcoin, plan::Plan, psbt::PsbtInputSatisfier};

/// Type used to finalize inputs of a Partially Signed Bitcoin Transaction (PSBT) using
/// a collection of pre-computed spending plans.
///
/// Finalizing a PSBT involves locating signatures and filling in the `final_script_sig`
/// and/or `final_script_witness` fields of the PSBT input, as specified in [BIP174]. The
/// [`Finalizer`] is able to satisfy inputs for which a valid signature has been provided using
/// the pre-computed spending [`Plan`] for each input. This process converts a PSBT input from a
/// partially signed state to a fully signed state, making it ready for extraction into a valid
/// Bitcoin [`Transaction`].
///
/// # BIP174 compliance
///
/// As required by [BIP174], finalization fails for any input whose declared sighash type
/// (`PSBT_IN_SIGHASH_TYPE`) disagrees with one of its signatures (see
/// [`FinalizeError::SighashType`]). When clearing the now-redundant per-input metadata, the UTXO
/// and any unknown or proprietary key-value pairs are preserved.
///
/// # Usage
///
/// Construct a [`Finalizer`] from a list of `(outpoint, plan)` pairs, or by calling
/// [`into_finalizer`] on a particular [`Selection`]. Use [`finalize_input`] to finalize a single
/// input, or [`finalize`] to finalize every input and return a map containing the result of
/// finalization at each index. Upon finalizing the PSBT, the [`Finalizer`] also clears metadata
/// from non-essential fields of the PSBT inputs and outputs, ensuring that only the necessary
/// information remains for transaction extraction.
///
/// # Example
///
/// ```rust,no_run
/// # use bdk_tx::PsbtParams;
/// # let secp = bitcoin::secp256k1::Secp256k1::new();
/// # let keymap = std::collections::BTreeMap::new();
/// # let selection: bdk_tx::Selection = unimplemented!();
/// // Create PSBT from a selection of inputs and outputs.
/// let mut psbt = selection.create_psbt(PsbtParams::default())?;
///
/// // Sign the PSBT using your preferred method.
/// let signer = bdk_tx::Signer(keymap);
/// let _ = psbt.sign(&signer, &secp);
///
/// // Finalize the PSBT.
/// let finalizer = selection.into_finalizer();
/// let finalize_map = finalizer.finalize(&mut psbt);
/// assert!(finalize_map.is_finalized());
///
/// // Extract the final transaction.
/// let tx = psbt.extract_tx()?;
/// # Ok::<_, anyhow::Error>(())
/// ```
///
/// [BIP174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#input-finalizer>
/// [`Selection`]: crate::Selection
/// [`into_finalizer`]: crate::Selection::into_finalizer
/// [`Plan`]: miniscript::plan::Plan
/// [`Transaction`]: bitcoin::Transaction
/// [`finalize_input`]: Finalizer::finalize_input
/// [`finalize`]: Finalizer::finalize
#[derive(Debug)]
pub struct Finalizer {
    pub(crate) plans: HashMap<OutPoint, Plan>,
}

impl Finalizer {
    /// Create.
    pub fn new(plans: impl IntoIterator<Item = (OutPoint, Plan)>) -> Self {
        Self {
            plans: plans.into_iter().collect(),
        }
    }

    /// Finalize a PSBT input and return whether finalization was successful or input was already
    /// finalized.
    ///
    /// # Errors
    ///
    /// - [`FinalizeError::SighashType`] if the input declares a sighash type via
    ///   `PSBT_IN_SIGHASH_TYPE` and one of its signatures uses a different type. As mandated by
    ///   [BIP174], a finalizer must reject such inputs.
    /// - [`FinalizeError::Satisfy`] if the spending plan associated with the PSBT input cannot be
    ///   satisfied with the data present in the PSBT.
    ///
    /// # Panics
    ///
    /// - If `input_index` is outside the bounds of the PSBT input vector.
    ///
    /// [BIP174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#input-finalizer>
    pub fn finalize_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
    ) -> Result<bool, FinalizeError> {
        // return true if already finalized.
        {
            let psbt_input = &psbt.inputs[input_index];
            if psbt_input.final_script_sig.is_some() || psbt_input.final_script_witness.is_some() {
                return Ok(true);
            }
        }

        let mut finalized = false;
        let outpoint = psbt
            .unsigned_tx
            .input
            .get(input_index)
            .expect("index out of range")
            .previous_output;
        if let Some(plan) = self.plans.get(&outpoint) {
            // BIP174: a finalizer must reject inputs carrying a signature whose sighash type does
            // not match the type declared by `PSBT_IN_SIGHASH_TYPE`.
            check_sighash_types(&psbt.inputs[input_index])?;

            let stfr = PsbtInputSatisfier::new(psbt, input_index);
            let (stack, script) = plan.satisfy(&stfr)?;
            // Clear all fields, restoring only what BIP174 says a finalizer must keep: the UTXO,
            // the unknown and proprietary key-value pairs, and the final scriptSig and witness.
            let original = core::mem::take(&mut psbt.inputs[input_index]);
            let psbt_input = &mut psbt.inputs[input_index];
            psbt_input.non_witness_utxo = original.non_witness_utxo;
            psbt_input.witness_utxo = original.witness_utxo;
            psbt_input.unknown = original.unknown;
            psbt_input.proprietary = original.proprietary;
            if !script.is_empty() {
                psbt_input.final_script_sig = Some(script);
            }
            if !stack.is_empty() {
                psbt_input.final_script_witness = Some(Witness::from_slice(&stack));
            }
            finalized = true;
        }

        Ok(finalized)
    }

    /// Attempt to finalize all of the inputs.
    ///
    /// This method returns a [`FinalizeMap`] that contains the result of finalization
    /// for each input.
    pub fn finalize(&self, psbt: &mut Psbt) -> FinalizeMap {
        let mut result = FinalizeMap(BTreeMap::new());

        for input_index in 0..psbt.inputs.len() {
            let psbt_input = &psbt.inputs[input_index];
            if psbt_input.final_script_sig.is_some() || psbt_input.final_script_witness.is_some() {
                continue;
            }
            result
                .0
                .insert(input_index, self.finalize_input(psbt, input_index));
        }

        // clear psbt outputs
        if result.is_finalized() {
            for psbt_output in &mut psbt.outputs {
                psbt_output.bip32_derivation.clear();
                psbt_output.tap_key_origins.clear();
                psbt_output.tap_internal_key.take();
            }
        }

        result
    }
}

/// Holds the results of finalization
#[derive(Debug)]
pub struct FinalizeMap(BTreeMap<usize, Result<bool, FinalizeError>>);

impl FinalizeMap {
    /// Whether all inputs were finalized
    pub fn is_finalized(&self) -> bool {
        self.0.values().all(|res| matches!(res, Ok(true)))
    }

    /// Get the results as a map of `input_index` to `finalize_input` result.
    pub fn results(self) -> BTreeMap<usize, Result<bool, FinalizeError>> {
        self.0
    }
}

/// Error returned when finalizing a PSBT input.
#[derive(Debug, PartialEq)]
pub enum FinalizeError {
    /// One of the input's signatures uses a sighash type that disagrees with the input's declared
    /// `PSBT_IN_SIGHASH_TYPE`.
    ///
    /// [BIP174] requires finalizers to fail in this case rather than produce a transaction whose
    /// signatures commit to a different sighash type than was declared.
    ///
    /// [BIP174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#input-finalizer>
    SighashType(SighashTypeMismatch),
    /// The input's spending [`Plan`] could not be satisfied with the data present in the PSBT.
    ///
    /// [`Plan`]: miniscript::plan::Plan
    Satisfy(miniscript::Error),
}

impl fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SighashType(e) => write!(f, "{e}"),
            Self::Satisfy(e) => write!(f, "failed to satisfy spending plan: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FinalizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SighashType(e) => Some(e),
            Self::Satisfy(e) => Some(e),
        }
    }
}

impl From<SighashTypeMismatch> for FinalizeError {
    fn from(e: SighashTypeMismatch) -> Self {
        Self::SighashType(e)
    }
}

impl From<miniscript::Error> for FinalizeError {
    fn from(e: miniscript::Error) -> Self {
        Self::Satisfy(e)
    }
}

/// A signature in a PSBT input uses a sighash type that disagrees with the input's declared
/// `PSBT_IN_SIGHASH_TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SighashTypeMismatch {
    /// The sighash type declared by the input's `PSBT_IN_SIGHASH_TYPE` field.
    pub declared: PsbtSighashType,
    /// The sighash type found on the offending signature.
    pub found: PsbtSighashType,
}

impl fmt::Display for SighashTypeMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "signature sighash type ({}) does not match the input's declared sighash type ({})",
            self.found, self.declared,
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashTypeMismatch {}

/// Verify that every signature present in `psbt_input` uses the sighash type declared by the
/// input's `PSBT_IN_SIGHASH_TYPE` field.
///
/// If the input does not declare a sighash type there is nothing to enforce, so this returns
/// `Ok(())`. BIP174 only requires finalizers to reject signatures that disagree with a *declared*
/// type; an undeclared type leaves signers free to choose.
fn check_sighash_types(psbt_input: &bitcoin::psbt::Input) -> Result<(), SighashTypeMismatch> {
    let declared = match psbt_input.sighash_type {
        Some(declared) => declared,
        None => return Ok(()),
    };

    // Both `EcdsaSighashType` and `TapSighashType` map onto a `PsbtSighashType`, so comparing the
    // raw `u32` representation works uniformly across signature kinds. For Taproot this naturally
    // captures the BIP-encoded distinction between 64-byte (implicit `SIGHASH_DEFAULT`) and
    // 65-byte (explicit trailing sighash byte) signatures.
    let check = |found: PsbtSighashType| -> Result<(), SighashTypeMismatch> {
        if found.to_u32() == declared.to_u32() {
            Ok(())
        } else {
            Err(SighashTypeMismatch { declared, found })
        }
    };

    for sig in psbt_input.partial_sigs.values() {
        check(sig.sighash_type.into())?;
    }
    if let Some(sig) = &psbt_input.tap_key_sig {
        check(sig.sighash_type.into())?;
    }
    for sig in psbt_input.tap_script_sigs.values() {
        check(sig.sighash_type.into())?;
    }

    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use crate::{
        FinalizeError, Finalizer, Output, PsbtParams, Selection, SighashTypeMismatch, Signer,
    };
    use bitcoin::psbt::raw;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{
        absolute, transaction, Amount, EcdsaSighashType, ScriptBuf, TapSighashType, TxIn, TxOut,
    };
    use miniscript::bitcoin;
    use miniscript::bitcoin::Transaction;
    use miniscript::plan::Assets;
    use miniscript::Descriptor;

    const TR_XPRV: &str = "tr(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/86h/1h/0h/0/*)";
    const WPKH_XPRV: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84h/1h/0h/0/*)";
    const PKH_XPRV: &str = "pkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/44h/1h/0h/0/*)";

    fn create_input_from_descriptor_at(
        descriptor: &str,
        derivation_index: u32,
    ) -> anyhow::Result<(crate::Input, miniscript::descriptor::KeyMap)> {
        let secp = Secp256k1::new();
        let (desc, keymap) = Descriptor::parse_descriptor(&secp, descriptor)?;
        let def_desc = desc.at_derivation_index(derivation_index)?;
        let script_pubkey = def_desc.script_pubkey();

        let assets = keymap.keys().fold(Assets::new(), |a, k| a.add(k.clone()));
        let plan = def_desc.plan(&assets).expect("failed to create plan");

        let prev_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                script_pubkey,
                value: Amount::from_sat(100_000),
            }],
        };

        let status = crate::ConfirmationStatus::new(1_000, Some(500_000_000))?;
        let input = crate::Input::from_prev_tx(plan, prev_tx, 0, Some(status))?;
        Ok((input, keymap))
    }

    fn derive_descriptor_at(
        descriptor: &str,
        derivation_index: u32,
    ) -> anyhow::Result<crate::DefiniteDescriptor> {
        let secp = Secp256k1::new();
        let (descriptor, _) = Descriptor::parse_descriptor(&secp, descriptor)?;
        Ok(descriptor.at_derivation_index(derivation_index)?)
    }

    #[test]
    fn test_finalize_single_input() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        let is_finalized = finalizer.finalize_input(&mut psbt, 0)?;
        assert!(is_finalized);
        assert!(psbt.inputs[0].final_script_witness.is_some());

        Ok(())
    }

    #[test]
    fn test_finalize_sets_final_script_sig() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(PKH_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        assert!(finalizer.finalize_input(&mut psbt, 0)?);
        assert!(psbt.inputs[0].final_script_sig.is_some());

        Ok(())
    }

    #[test]
    fn test_finalize_all_inputs() -> anyhow::Result<()> {
        let (input_0, keymap_0) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let (input_1, keymap_1) = create_input_from_descriptor_at(TR_XPRV, 1)?;
        let (input_2, keymap_2) = create_input_from_descriptor_at(TR_XPRV, 2)?;
        let taproot_output_descriptor = derive_descriptor_at(TR_XPRV, 10)?;
        let wpkh_output_descriptor = derive_descriptor_at(WPKH_XPRV, 11)?;

        let selection = Selection::new(
            vec![input_0, input_1, input_2],
            vec![
                Output::with_descriptor(taproot_output_descriptor, Amount::from_sat(20_000)),
                Output::with_descriptor(wpkh_output_descriptor, Amount::from_sat(22_000)),
            ],
        );

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        assert!(!psbt.outputs[0].tap_key_origins.is_empty());
        assert!(psbt.outputs[0].tap_internal_key.is_some());
        assert!(!psbt.outputs[1].bip32_derivation.is_empty());

        let secp = Secp256k1::new();
        let mut combined_keymap = keymap_0;
        combined_keymap.extend(keymap_1);
        combined_keymap.extend(keymap_2);
        let signer = Signer(combined_keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        let finalized = finalizer.finalize(&mut psbt);
        assert!(finalized.is_finalized());
        let finalize_results = finalized.results();

        assert!(finalize_results
            .values()
            .all(|result| matches!(result, Ok(true))));

        for psbt_input in psbt.inputs.iter() {
            assert!(psbt_input.final_script_witness.is_some());
        }

        // Output metadata should be cleared after finalization.
        for psbt_output in psbt.outputs.iter() {
            assert!(psbt_output.bip32_derivation.is_empty());
            assert!(psbt_output.tap_key_origins.is_empty());
            assert!(psbt_output.tap_internal_key.is_none());
        }

        Ok(())
    }

    #[test]
    fn test_finalize_missing_plan() -> anyhow::Result<()> {
        let (input_0, keymap_0) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let (input_1, keymap_1) = create_input_from_descriptor_at(TR_XPRV, 1)?;
        let taproot_output_descriptor = derive_descriptor_at(TR_XPRV, 10)?;
        let wpkh_output_descriptor = derive_descriptor_at(WPKH_XPRV, 11)?;
        let finalizer = Finalizer::new([(
            input_0.prev_outpoint(),
            input_0.plan().cloned().expect("plan must exist"),
        )]);

        let selection = Selection::new(
            vec![input_0, input_1],
            vec![
                Output::with_descriptor(taproot_output_descriptor, Amount::from_sat(20_000)),
                Output::with_descriptor(wpkh_output_descriptor, Amount::from_sat(22_000)),
            ],
        );

        let mut psbt = selection.create_psbt(PsbtParams::default())?;

        let tap_key_origins = psbt.outputs[0].tap_key_origins.clone();
        let tap_internal_key = psbt.outputs[0].tap_internal_key;
        let bip32_derivation = psbt.outputs[1].bip32_derivation.clone();

        let secp = Secp256k1::new();
        let mut combined_keymap = keymap_0;
        combined_keymap.extend(keymap_1);
        let signer = Signer(combined_keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        let finalized = finalizer.finalize(&mut psbt);
        assert!(!finalized.is_finalized());
        let finalize_results = finalized.results();

        assert!(matches!(finalize_results.get(&0), Some(Ok(true))));
        assert!(matches!(finalize_results.get(&1), Some(Ok(false))));
        assert!(psbt.inputs[0].final_script_witness.is_some());
        assert!(psbt.inputs[1].final_script_witness.is_none());
        assert_eq!(psbt.outputs[0].tap_key_origins, tap_key_origins);
        assert_eq!(psbt.outputs[0].tap_internal_key, tap_internal_key);
        assert_eq!(psbt.outputs[1].bip32_derivation, bip32_derivation);

        Ok(())
    }

    #[test]
    fn test_finalize_returns_error_and_preserves_output_metadata() -> anyhow::Result<()> {
        let (input, _) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let taproot_output_descriptor = derive_descriptor_at(TR_XPRV, 10)?;
        let wpkh_output_descriptor = derive_descriptor_at(WPKH_XPRV, 11)?;
        let selection = Selection::new(
            vec![input],
            vec![
                Output::with_descriptor(taproot_output_descriptor, Amount::from_sat(20_000)),
                Output::with_descriptor(wpkh_output_descriptor, Amount::from_sat(22_000)),
            ],
        );

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        let tap_key_origins = psbt.outputs[0].tap_key_origins.clone();
        let tap_internal_key = psbt.outputs[0].tap_internal_key;
        let bip32_derivation = psbt.outputs[1].bip32_derivation.clone();

        // Skip signing to create error
        let finalized = finalizer.finalize(&mut psbt);
        assert!(!finalized.is_finalized());
        let finalize_results = finalized.results();

        assert!(matches!(finalize_results.get(&0), Some(Err(_))));
        assert!(psbt.inputs[0].final_script_sig.is_none());
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert_eq!(psbt.outputs[0].tap_key_origins, tap_key_origins);
        assert_eq!(psbt.outputs[0].tap_internal_key, tap_internal_key);
        assert_eq!(psbt.outputs[1].bip32_derivation, bip32_derivation);

        Ok(())
    }

    #[test]
    fn test_already_finalized_input() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        assert!(finalizer.finalize_input(&mut psbt, 0)?);

        let final_script_sig = psbt.inputs[0].final_script_sig.clone();
        let final_script_witness = psbt.inputs[0].final_script_witness.clone();

        // 2nd finalize_input should not change anything
        assert!(finalizer.finalize_input(&mut psbt, 0)?);
        assert_eq!(psbt.inputs[0].final_script_sig, final_script_sig);
        assert_eq!(psbt.inputs[0].final_script_witness, final_script_witness);

        let finalized = finalizer.finalize(&mut psbt);
        assert!(finalized.is_finalized());
        let results = finalized.results();

        assert!(results.is_empty());
        assert_eq!(psbt.inputs[0].final_script_sig, final_script_sig);
        assert_eq!(psbt.inputs[0].final_script_witness, final_script_witness);

        Ok(())
    }

    #[test]
    fn test_finalize_rejects_taproot_sighash_type_mismatch() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        // Sign without a declared sighash type, producing a 64-byte `SIGHASH_DEFAULT` signature.
        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        // Now declare a conflicting sighash type. The finalizer must refuse to finalize.
        psbt.inputs[0].sighash_type = Some(TapSighashType::All.into());

        let err = finalizer
            .finalize_input(&mut psbt, 0)
            .expect_err("finalization must fail on sighash mismatch");
        assert_eq!(
            err,
            FinalizeError::SighashType(SighashTypeMismatch {
                declared: TapSighashType::All.into(),
                found: TapSighashType::Default.into(),
            })
        );

        // The input must be left untouched (not finalized).
        assert!(psbt.inputs[0].final_script_sig.is_none());
        assert!(psbt.inputs[0].final_script_witness.is_none());

        Ok(())
    }

    #[test]
    fn test_finalize_rejects_ecdsa_sighash_type_mismatch() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(WPKH_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        // Sign without a declared sighash type, producing a `SIGHASH_ALL` signature.
        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        // Declare a conflicting sighash type.
        psbt.inputs[0].sighash_type = Some(EcdsaSighashType::Single.into());

        let err = finalizer
            .finalize_input(&mut psbt, 0)
            .expect_err("finalization must fail on sighash mismatch");
        assert_eq!(
            err,
            FinalizeError::SighashType(SighashTypeMismatch {
                declared: EcdsaSighashType::Single.into(),
                found: EcdsaSighashType::All.into(),
            })
        );

        assert!(psbt.inputs[0].final_script_sig.is_none());
        assert!(psbt.inputs[0].final_script_witness.is_none());

        Ok(())
    }

    #[test]
    fn test_finalize_accepts_matching_declared_sighash_type() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        // Declare `SIGHASH_DEFAULT` up front. (`SIGHASH_DEFAULT` keeps the 64-byte signature size
        // assumed by the plan; a 65-byte sighash would need a plan built for that size.)
        let params = PsbtParams {
            sighash_type: Some(TapSighashType::Default.into()),
            ..Default::default()
        };
        let mut psbt = selection.create_psbt(params)?;
        let finalizer = selection.into_finalizer();
        assert_eq!(
            psbt.inputs[0].sighash_type,
            Some(TapSighashType::Default.into())
        );

        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        // The declared type matches the signature, so the sighash check passes and the input
        // finalizes.
        assert!(finalizer.finalize_input(&mut psbt, 0)?);
        assert!(psbt.inputs[0].final_script_witness.is_some());

        Ok(())
    }

    #[test]
    fn test_finalize_preserves_unknown_and_proprietary_fields() -> anyhow::Result<()> {
        let (input, keymap) = create_input_from_descriptor_at(TR_XPRV, 0)?;
        let output = Output::with_script(ScriptBuf::new(), Amount::from_sat(9_000));
        let selection = Selection::new(vec![input], vec![output]);

        let mut psbt = selection.create_psbt(PsbtParams::default())?;
        let finalizer = selection.into_finalizer();

        // Attach unknown and proprietary metadata that BIP174 says a finalizer must preserve.
        let unknown_key = raw::Key {
            type_value: 0x77,
            key: vec![0xaa, 0xbb],
        };
        psbt.inputs[0]
            .unknown
            .insert(unknown_key.clone(), vec![1u8, 2, 3]);
        let prop_key = raw::ProprietaryKey {
            prefix: b"bdk".to_vec(),
            subtype: 0u8,
            key: vec![0x01],
        };
        psbt.inputs[0]
            .proprietary
            .insert(prop_key.clone(), vec![4u8, 5, 6]);

        let secp = Secp256k1::new();
        let signer = Signer(keymap);
        psbt.sign(&signer, &secp).expect("signing failed");

        // Taproot metadata is present before finalization.
        assert!(!psbt.inputs[0].tap_key_origins.is_empty());
        assert!(psbt.inputs[0].tap_internal_key.is_some());

        assert!(finalizer.finalize_input(&mut psbt, 0)?);
        assert!(psbt.inputs[0].final_script_witness.is_some());

        // Non-essential signing metadata is cleared.
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.inputs[0].tap_key_origins.is_empty());
        assert!(psbt.inputs[0].tap_internal_key.is_none());

        // Unknown and proprietary fields survive.
        assert_eq!(
            psbt.inputs[0].unknown.get(&unknown_key),
            Some(&vec![1u8, 2, 3])
        );
        assert_eq!(
            psbt.inputs[0].proprietary.get(&prop_key),
            Some(&vec![4u8, 5, 6])
        );

        Ok(())
    }
}
