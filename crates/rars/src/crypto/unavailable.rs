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
