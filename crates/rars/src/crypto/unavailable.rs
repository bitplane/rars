//! Uninhabited reader storage preserves shared generic extraction types when
//! encrypted implementations are excluded. Constructors always report availability.
use crate::{Error, Result};
use std::convert::Infallible;
use std::marker::PhantomData;
pub(crate) struct Reader<R, B = ()> {
    unavailable: Infallible,
    _parameters: PhantomData<(R, B)>,
}
impl<R, B> Reader<R, B> {
    pub(crate) fn with_allowance(
        _inner: R,
        _version: u8,
        _password: &[u8],
        _salt: Option<[u8; 8]>,
        _key_cache: &crate::key_cache::KeyCache,
        _allowance: &B,
    ) -> Result<Self> {
        Err(Error::FeatureDisabled {
            feature: "encryption",
        })
    }
}
impl<R> Reader<R> {
    pub(crate) fn with_keys(_inner: R, _key: [u8; 32], _iv: [u8; 16]) -> Result<Self> {
        Err(Error::FeatureDisabled {
            feature: "encryption",
        })
    }
}
impl<R, B> std::io::Read for Reader<R, B> {
    fn read(&mut self, _out: &mut [u8]) -> std::io::Result<usize> {
        match self.unavailable {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn constructors_refuse_before_input_or_workspace_access() {
        struct Unread;
        impl std::io::Read for Unread {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("disabled crypto must not read input")
            }
        }
        let allowance = crate::codec::workspace::Allowance::limited(0);
        let result = Reader::with_allowance(
            Unread,
            29,
            b"password",
            None,
            &crate::key_cache::KeyCache::default(),
            &allowance,
        );
        assert!(matches!(
            result,
            Err(Error::FeatureDisabled {
                feature: "encryption"
            })
        ));
        assert_eq!(allowance.used(), 0);
        let result = Reader::with_keys(Unread, [0; 32], [0; 16]);
        assert!(matches!(
            result,
            Err(Error::FeatureDisabled {
                feature: "encryption"
            })
        ));
    }
}
