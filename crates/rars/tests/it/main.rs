//! The library's integration tests, as one test binary.
//!
//! Every file in `tests/` is a binary of its own that has to be compiled and
//! linked against rars separately, and at one per file that was most of the
//! time CI spent building tests. Each file here is a module instead, named as
//! the binary it used to be, so `cargo test -p rars --test it rar50_golden::`
//! (or a nextest filter) still picks out one file's tests. Add new test files
//! here as modules, gated on the features they need, rather than beside
//! `tests/encoder_memory_regression.rs`: that one stays separate because CI
//! builds it alone under single feature sets, where it is the only thing
//! worth compiling.
//!
//! The helpers in `tests/support` are compiled once, at this root, so the
//! modules share one scratch-directory counter.

#[cfg(feature = "write")]
#[path = "../support/scratch.rs"]
mod scratch;
#[cfg(feature = "write")]
#[path = "../support/volume_size.rs"]
mod volume_size;

#[cfg(feature = "write")]
mod builder_directories;
#[cfg(feature = "write")]
mod builder_file_comments;
#[cfg(feature = "write")]
mod builder_identity;
#[cfg(feature = "write")]
mod builder_metadata;
#[cfg(feature = "write")]
mod builder_output;
#[cfg(feature = "write")]
mod builder_symlinks;
#[cfg(feature = "write")]
mod builder_timestamps;
#[cfg(feature = "write")]
mod comment_options;
#[cfg(feature = "encryption")]
mod crypto_api;
#[cfg(feature = "write")]
mod extract_with_volumes;
#[cfg(feature = "write")]
mod extraction_control;
#[cfg(feature = "write")]
mod extraction_links;
#[cfg(all(feature = "write", feature = "encryption"))]
mod legacy_builder_path_streaming;
#[cfg(feature = "write")]
mod legacy_builder_sources;
#[cfg(feature = "write")]
mod legacy_codec_adapters;
mod legacy_compressed_volumes;
#[cfg(feature = "write")]
mod legacy_end_block;
#[cfg(feature = "write")]
mod legacy_large_members;
#[cfg(feature = "write")]
mod legacy_large_volumes;
#[cfg(feature = "write")]
mod legacy_name_encoding;
#[cfg(all(
    feature = "write",
    feature = "parallel",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
mod legacy_parallel_retention;
mod legacy_streaming_volumes;
mod legacy_volume_set_members;
#[cfg(feature = "write")]
mod legacy_writer_cancellation;
#[cfg(feature = "write")]
mod legacy_writer_errors;
#[cfg(feature = "write")]
mod member_selection;
mod ppmd_regressions;
#[cfg(feature = "write")]
mod producer_marker;
#[cfg(feature = "write")]
mod producer_marker_legacy;
#[cfg(feature = "write")]
mod producer_marker_old;
#[cfg(feature = "write")]
mod rar13_fixtures;
#[cfg(feature = "write")]
mod rar15_40_fixtures;
#[cfg(all(feature = "write", feature = "encryption"))]
mod rar29_cmt_comments;
#[cfg(all(feature = "write", feature = "encryption", feature = "recovery"))]
mod rar50_encrypted_volumes;
#[cfg(feature = "write")]
mod rar50_fixtures;
#[cfg(feature = "write")]
mod rar50_golden;
#[cfg(feature = "write")]
mod rar50_large_member_filters;
#[cfg(all(feature = "write", feature = "parallel"))]
mod rar50_shared_block_windows;
#[cfg(feature = "write")]
mod rar50_solid_filters;
#[cfg(feature = "write")]
mod rar50_split_limits;
mod rarvm_regressions;
mod reader_32bit_lengths;
#[cfg(feature = "write")]
mod reader_cancellation;
#[cfg(all(
    feature = "write",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
mod reader_decode_workers;
#[cfg(feature = "write")]
mod reader_dictionary_limit;
#[cfg(feature = "write")]
mod reader_failure_output;
#[cfg(feature = "write")]
mod reader_failure_paths;
#[cfg(feature = "write")]
mod reader_header_limits;
#[cfg(feature = "write")]
mod reader_output_limit;
#[cfg(all(
    feature = "write",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
mod reader_scratch;
#[cfg(feature = "write")]
mod reader_signatures;
#[cfg(feature = "write")]
mod reader_source;
#[cfg(feature = "write")]
mod reader_stored_lengths;
#[cfg(feature = "write")]
mod reader_verification;
#[cfg(feature = "write")]
mod reader_workspace;
#[cfg(all(feature = "write", feature = "recovery"))]
mod repair_cancellation;
#[cfg(all(feature = "write", feature = "recovery"))]
mod repair_streaming;
#[cfg(feature = "write")]
mod rewrite_settings;
#[cfg(all(
    feature = "write",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
mod rewrite_staging;
#[cfg(feature = "write")]
mod source_consistency;
#[cfg(feature = "write")]
mod split_continuation_names;
#[cfg(feature = "write")]
mod truncated_volumes;
#[cfg(feature = "write")]
mod volume_names;
#[cfg(all(feature = "write", feature = "encryption", feature = "recovery"))]
mod volume_size_ceiling;
#[cfg(feature = "write")]
mod write_progress;
#[cfg(feature = "write")]
mod writer_aggregate_limit;
#[cfg(feature = "write")]
mod writer_preparation_limit;
#[cfg(feature = "write")]
mod writer_spool_limit;
#[cfg(feature = "write")]
mod writer_stored_residency;
