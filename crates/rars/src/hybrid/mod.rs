//! Opt-in hybrid compression planning and its exact, externally stored repeat index.
//!
//! The index is independent of a RAR encoder's minimum match length, dictionary
//! and search-depth policies. Construction is online; occurrence queries are
//! available between members, after a unique virtual terminator makes every
//! suffix explicit. Captured sources keep their backing storage alive.

mod index;
mod options;

pub use index::{IndexLimits, Occurrence, RepeatIndex};
pub use options::{
    choose_minimax, dictionary_shortlist, DictionaryMeasurement, DictionaryStats,
    HybridArchitecture, HybridOptions, HybridProfile,
};

#[cfg(test)]
mod tests;
