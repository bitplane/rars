// The PPMd model's pool: a block of the size the archive declares, of which a
// model on a short member reaches only a few pages. The budget is charged for
// what the model reaches, which is right only if untouched pages cost nothing.
//
// A zeroed `Vec` keeps that promise while the allocator maps a fresh block,
// but allocators keep freed blocks this large for reuse and clear them in
// full when they hand them back. With glibc, once the first pool was freed
// every later one came back cleared, so each worker testing PPMd members held
// the whole declared size, 25 MiB at RAR 3's default (#553). On Unix the pool
// is therefore a private anonymous mapping of its own: pages are committed
// when the model first touches them and all of them are returned when it is
// dropped. Elsewhere it stays a zeroed `Vec`.
#![allow(unsafe_code)]

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

#[cfg(unix)]
mod imp {
    use std::ptr::NonNull;

    pub(super) struct Pool {
        ptr: NonNull<u8>,
        len: usize,
    }

    // SAFETY: the pool owns its mapping alone, as a `Box<[u8]>` owns its
    // bytes, and hands out access only through `&self` and `&mut self`.
    unsafe impl Send for Pool {}
    unsafe impl Sync for Pool {}

    impl Pool {
        pub(super) fn empty() -> Self {
            Self {
                ptr: NonNull::dangling(),
                len: 0,
            }
        }

        pub(super) fn zeroed(len: usize) -> Self {
            if len == 0 {
                return Self::empty();
            }
            // SAFETY: a new private anonymous mapping at an address of the
            // kernel's choosing touches no memory this process already uses.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            match NonNull::new(ptr.cast::<u8>()) {
                Some(ptr) if ptr.as_ptr() != libc::MAP_FAILED.cast() => Self { ptr, len },
                // Out of address space: fail as `vec![0; len]` would.
                _ => std::alloc::handle_alloc_error(
                    std::alloc::Layout::array::<u8>(len).expect("pool size fits a layout"),
                ),
            }
        }

        #[inline(always)]
        pub(super) fn as_slice(&self) -> &[u8] {
            // SAFETY: `ptr` is `len` readable bytes (or dangling with `len`
            // 0), mapped zeroed and only written through `as_mut_slice`.
            unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }

        #[inline(always)]
        pub(super) fn as_mut_slice(&mut self) -> &mut [u8] {
            // SAFETY: as above, and `&mut self` makes this the only borrow.
            unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
        }
    }

    impl Drop for Pool {
        fn drop(&mut self) {
            if self.len != 0 {
                // SAFETY: the mapping made in `zeroed`, unmapped once; no
                // borrow of it can outlive `self`.
                unsafe {
                    libc::munmap(self.ptr.as_ptr().cast(), self.len);
                }
            }
        }
    }
}

#[cfg(not(unix))]
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
}
