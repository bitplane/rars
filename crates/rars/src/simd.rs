// Allowed `unsafe` for SIMD loads, stores and dispatched calls. The only other
// module allowed it is `codec::ppmd::pool`, which maps the PPMd model.
#![allow(unsafe_code)]

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon"
))]
pub(crate) mod blake2s;
