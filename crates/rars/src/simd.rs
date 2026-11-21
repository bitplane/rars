// The one module allowed `unsafe`, for SIMD loads, stores and dispatched calls.
#![allow(unsafe_code)]

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon"
))]
pub(crate) mod blake2s;
