//! Streaming a large member through `Builder::write_to_path` is tested inside
//! the crate (`rar15_40/write/builder_path_tests.rs`), where the test can
//! lower the size members stream above.

use rars::{ArchiveReader, ArchiveVersion, Builder, EntrySource};

use crate::scratch;

#[test]
fn write_to_path_round_trips_encrypted_and_solid_legacy_archives() {
    let dir = scratch::case("builder-path-legacy-encrypted");
    let payload = b"legacy payload through a seekable file\n".repeat(64);
    for (index, (header_encryption, solid)) in [(false, false), (true, false), (true, true)]
        .into_iter()
        .enumerate()
    {
        let mut builder = Builder::new(ArchiveVersion::Rar40)
            .password(Some(b"secret".to_vec()))
            .header_encryption(header_encryption)
            .solid(solid);
        for name in [b"first".as_slice(), b"second"] {
            builder
                .add_source(
                    name.to_vec(),
                    EntrySource::from_bytes(payload.clone()),
                    None,
                    None,
                )
                .unwrap();
        }
        let path = dir.join(format!("{index}.rar"));
        builder.write_to_path(&path, None).unwrap();
        let archive = ArchiveReader::read_path_with_options(
            &path,
            rars::ArchiveReadOptions::with_password(b"secret"),
        )
        .unwrap();
        for name in [b"first".as_slice(), b"second"] {
            assert_eq!(
                archive.read_member(name, Some(b"secret")).unwrap().unwrap(),
                payload,
                "header_encryption={header_encryption} solid={solid}"
            );
        }
    }
}
