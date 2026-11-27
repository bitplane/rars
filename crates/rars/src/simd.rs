// The one module allowed `unsafe`, for SIMD loads, stores and dispatched calls.
#![allow(unsafe_code)]

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon"
))]
pub(crate) mod blake2s;

/// Asks the cache for the line holding `data[index]`, ahead of a load the
/// caller expects to miss. Only a hint: an index past the end is ignored, and
/// targets without a prefetch instruction here do nothing.
#[cfg(feature = "write")]
#[inline(always)]
pub(crate) fn prefetch<T>(data: &[T], index: usize) {
    #[cfg(target_arch = "x86_64")]
    if let Some(item) = data.get(index) {
        // SAFETY: a prefetch never faults and reads nothing back, and the
        // pointer comes from a live reference besides.
        unsafe {
            core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(
                (item as *const T).cast(),
            )
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (data, index);
}
