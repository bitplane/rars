#![cfg_attr(feature = "fast", feature(portable_simd))]

//! Version-specific RAR archive format support.
//!
//! This crate contains the wire-format parsers, writers, recovery handling, and
//! extraction orchestration used by the high-level `rars` facade. It keeps the
//! concrete RAR families separate so callers can inspect format-specific header
//! fields when they need that fidelity.

pub mod detect;
pub mod error;
pub mod features;
pub mod rar13;
pub mod rar15_40;
pub mod rar50;
pub mod version;

mod fast;
mod io_util;
#[cfg(feature = "parallel")]
mod parallel;
mod source;
mod volume_extract;
mod x86_filter_scan;

pub use detect::{detect_archive_family, find_archive_start, ArchiveSignature, SFX_SCAN_LIMIT};
pub use error::{Error, Result};
pub use features::FeatureSet;
pub use version::{ArchiveFamily, ArchiveVersion};

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Options used while parsing or extracting archives.
pub struct ArchiveReadOptions<'a> {
    /// Password bytes used for encrypted headers or payloads.
    pub password: Option<&'a [u8]>,
}

impl<'a> ArchiveReadOptions<'a> {
    /// Creates read options without a password.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates read options with a password.
    pub fn with_password(password: &'a [u8]) -> Self {
        Self {
            password: Some(password),
        }
    }
}
