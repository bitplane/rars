use rars::EntrySource;
use std::{io::Read, sync::Arc};

#[test]
fn byte_sources_are_rewindable_without_copying() {
    let source = EntrySource::from_bytes(Arc::<[u8]>::from(&b"hello"[..]));
    let mut first = source.open().unwrap();
    let mut second = source.open().unwrap();
    let mut a = Vec::new();
    let mut b = Vec::new();
    first.read_to_end(&mut a).unwrap();
    second.read_to_end(&mut b).unwrap();
    assert_eq!(a, b"hello");
    assert_eq!(b, b"hello");
}
