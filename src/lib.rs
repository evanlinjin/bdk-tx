//! `bdk_tx`
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![warn(missing_docs)]
#![no_std]

extern crate alloc;

#[macro_use]
#[cfg(feature = "std")]
extern crate std;

mod anti_fee_sniping;
mod canonical_unspents;
mod input;
mod input_candidates;
mod output;
mod psbt_finalizer;
mod rbf;
mod selection;
mod selector;
mod signer;
mod tx_template;

pub use anti_fee_sniping::AntiFeeSnipingError;
pub use canonical_unspents::*;
pub use input::*;
pub use input_candidates::*;
pub use miniscript;
pub use miniscript::bitcoin;
use miniscript::{DefiniteDescriptorKey, Descriptor};
pub use output::*;
pub use psbt_finalizer::*;
pub use rbf::*;
pub use selection::*;
pub use selector::*;
pub use signer::*;
pub use tx_template::*;

#[cfg(feature = "std")]
pub(crate) mod collections {
    #![allow(unused)]
    pub use std::collections::*;
}

#[cfg(not(feature = "std"))]
pub(crate) mod collections {
    #![allow(unused)]
    pub type HashMap<K, V> = alloc::collections::BTreeMap<K, V>;
    pub type HashSet<T> = alloc::collections::BTreeSet<T>;
    pub use alloc::collections::*;
}

/// Definite descriptor.
pub type DefiniteDescriptor = Descriptor<DefiniteDescriptorKey>;

/// Extension trait for converting [`bitcoin::FeeRate`] to [`bdk_coin_select::FeeRate`].
pub trait FeeRateExt {
    /// Convert to a [`bdk_coin_select::FeeRate`].
    fn into_cs_feerate(self) -> bdk_coin_select::FeeRate;
}

impl FeeRateExt for bitcoin::FeeRate {
    fn into_cs_feerate(self) -> bdk_coin_select::FeeRate {
        bdk_coin_select::FeeRate::from_sat_per_wu(self.to_sat_per_kwu() as f32 / 1000.0)
    }
}
