//! Public API tests share one integration-test target.

#[cfg(feature = "write")]
mod builder;

#[cfg(feature = "write")]
mod codec_rar13;

#[cfg(feature = "write")]
mod codec_rar20;

#[cfg(feature = "write")]
mod codec_rar29;

#[cfg(feature = "write")]
mod codec_rar50;

mod crc32;

mod detect;

mod error;

#[cfg(feature = "write")]
mod facade;

mod feature_matrix;

mod filename;

mod filter;

#[cfg(feature = "write")]
mod legacy_reader;

#[cfg(feature = "write")]
mod legacy_writer;

#[cfg(feature = "write")]
mod rar13_writer;

#[cfg(feature = "recovery")]
mod rar3_recovery;

#[cfg(feature = "write")]
mod rar50_extract;

#[cfg(feature = "write")]
mod rar50_reader;

#[cfg(feature = "write")]
mod rar50_writer;

#[cfg(feature = "recovery")]
mod rar5_recovery;

#[cfg(feature = "write")]
mod streaming;

#[cfg(feature = "write")]
mod support;

mod timestamp;

mod version;

mod volume_name;

#[cfg(feature = "write")]
mod write_plan;
