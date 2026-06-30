//! Deprecated as a standalone public dependency: this crate remains an
//! implementation detail for the current release. New Rust users should depend
//! on the `rars` crate instead.
//!
//! RAR legacy and modern archive encryption primitives used by `rars`.

pub mod rar13;
pub mod rar15;
pub mod rar20;
pub mod rar30;
pub mod rar50;
