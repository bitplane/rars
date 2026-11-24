// The PPMd model's pool: a block of the size the archive declares, of which a
// model on a short member reaches only a few pages. The budget is charged for
// what the model reaches, which is right only if untouched pages cost nothing.
//
// A zeroed `Vec` keeps that promise while the allocator maps a fresh block,
// but allocators keep freed blocks this large for reuse and clear them in
// full when they hand them back. With glibc, once the first pool was freed
// every later one came back cleared, so each worker testing PPMd members held
// the whole declared size, 25 MiB at RAR 3's default (#553). On Unix and
// Windows the pool is therefore an anonymous mapping of its own, made by
// `memmap2`: pages are committed when the model first touches them and all of
// them are returned when it is dropped. Elsewhere it stays a zeroed `Vec`.

/// Zeroed bytes, read and written as a slice.
pub(super) struct Pool(imp::Pool);

impl Pool {
    pub(super) fn empty() -> Self {
        Self(imp::Pool::empty())
    }

    pub(super) fn zeroed(len: usize) -> Self {
        Self(imp::Pool::zeroed(len))
    }
}

impl std::ops::Deref for Pool {
    type Target = [u8];
    #[inline(always)]
    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::ops::DerefMut for Pool {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool").field("len", &self.len()).finish()
    }
}

#[cfg(any(unix, windows))]
mod imp {
    use memmap2::{MmapMut, MmapOptions};

    /// Even an empty pool is a mapping (memmap2 maps a page for it), so the
    /// model's every access reaches the slice without a branch.
    pub(super) struct Pool(MmapMut);

    impl Pool {
        pub(super) fn empty() -> Self {
            Self::zeroed(0)
        }

        pub(super) fn zeroed(len: usize) -> Self {
            match MmapOptions::new().len(len).map_anon() {
                Ok(map) => Self(map),
                // Out of address space: fail as `vec![0; len]` would.
                Err(_) => std::alloc::handle_alloc_error(
                    std::alloc::Layout::array::<u8>(len).expect("pool size fits a layout"),
                ),
            }
        }

        #[inline(always)]
        pub(super) fn as_slice(&self) -> &[u8] {
            &self.0
        }

        #[inline(always)]
        pub(super) fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) struct Pool(Vec<u8>);

    impl Pool {
        pub(super) fn empty() -> Self {
            Self(Vec::new())
        }

        pub(super) fn zeroed(len: usize) -> Self {
            Self(vec![0; len])
        }

        #[inline(always)]
        pub(super) fn as_slice(&self) -> &[u8] {
            &self.0
        }

        #[inline(always)]
        pub(super) fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Pool;

    #[test]
    fn a_pool_starts_zeroed_and_keeps_what_is_written() {
        let mut pool = Pool::zeroed(3 << 20);
        assert_eq!(pool.len(), 3 << 20);
        assert!(pool.iter().all(|&byte| byte == 0));
        pool[0] = 1;
        let last = pool.len() - 1;
        pool[last] = 2;
        assert_eq!((pool[0], pool[last]), (1, 2));
        assert!(Pool::empty().is_empty());
        assert!(Pool::zeroed(0).is_empty());
    }

    #[test]
    fn a_pool_can_move_between_and_be_shared_by_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Pool>();
    }
}
