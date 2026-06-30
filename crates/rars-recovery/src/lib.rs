//! Recovery-record primitives shared by RAR writer and repair code.
//!
//! Deprecated as a standalone public dependency: this crate remains an
//! implementation detail for the current release. New Rust users should depend
//! on the `rars` crate instead.
//!
//! RAR 5 recovery data uses GF(2^16) with reduction polynomial `0x1100b`
//! and a Cauchy encoder matrix. This crate intentionally exposes the field
//! and matrix building blocks before wiring them into archive serialization.

pub mod rar3;
pub mod rar5;
