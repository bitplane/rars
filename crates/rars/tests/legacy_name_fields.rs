//! RAR 1.3-4 header fields read as UnRAR reads them: name fields are C
//! strings, a damaged Unicode name falls back to the legacy one, and an
//! encrypted member with nothing in it needs no password.

use rars::{filename::LegacyNameEncoding, ArchiveReader};

#[cfg(feature = "encryption")]
const FHD_PASSWORD: u16 = 0x0004;
const FHD_UNICODE: u16 = 0x0200;

struct Member<'a> {
    name: &'a [u8],
    flags: u16,
    data: &'a [u8],
    unp_size: u32,
    crc: u32,
    unp_ver: u8,
    method: u8,
}

fn stored<'a>(name: &'a [u8], flags: u16, data: &'a [u8]) -> Member<'a> {
    Member {
        name,
        flags,
        data,
        unp_size: data.len() as u32,
        crc: rars::crc32::crc32(data),
        unp_ver: 29,
        method: 0x30,
    }
}

fn block(out: &mut Vec<u8>, head_type: u8, flags: u16, body: &[u8], data: &[u8]) {
    let mut header = vec![head_type];
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(&(7 + body.len() as u16).to_le_bytes());
    header.extend_from_slice(body);
    out.extend_from_slice(&(rars::crc32::crc32(&header) as u16).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
}

/// A RAR 2.9 archive whose file headers carry the given raw name fields.
fn rar29(members: &[Member<'_>]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x00".to_vec();
    block(&mut out, 0x73, 0, &[0; 6], &[]);
    for member in members {
        let mut body = Vec::new();
        body.extend_from_slice(&(member.data.len() as u32).to_le_bytes());
        body.extend_from_slice(&member.unp_size.to_le_bytes());
        body.push(2);
        body.extend_from_slice(&member.crc.to_le_bytes());
        body.extend_from_slice(&0x5a21_0000u32.to_le_bytes());
        body.push(member.unp_ver);
        body.push(member.method);
        body.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        body.extend_from_slice(&0x20u32.to_le_bytes());
        body.extend_from_slice(member.name);
        block(&mut out, 0x74, 0x8000 | member.flags, &body, member.data);
    }
    block(&mut out, 0x7b, 0x4000, &[], &[]);
    out
}

/// Each member's name and extracted data, in archive order.
type Extracted = Vec<(Vec<u8>, Vec<u8>)>;

fn extract(archive: &rars::Archive, password: Option<&[u8]>) -> rars::Result<Extracted> {
    let outputs = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = outputs.clone();
    archive.extract_to(password, move |meta| {
        sink.borrow_mut().push((meta.name.clone(), Vec::new()));
        Ok(Box::new(Output(sink.clone())))
    })?;
    Ok(outputs.take())
}

struct Output(std::rc::Rc<std::cell::RefCell<Extracted>>);

impl std::io::Write for Output {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .borrow_mut()
            .last_mut()
            .unwrap()
            .1
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn legacy_names_end_at_their_first_nul_and_keep_control_bytes() {
    let archive = ArchiveReader::read_owned(rar29(&[
        stored(b"nul\0tail.txt", 0, b"one"),
        stored(b"ctl\x12x.txt", 0, b"two"),
    ]))
    .unwrap();
    let names: Vec<_> = archive.members().map(|m| m.meta.name.clone()).collect();
    assert_eq!(names, [b"nul".to_vec(), b"ctl\x12x.txt".to_vec()]);
    assert_eq!(
        extract(&archive, None).unwrap(),
        [
            (b"nul".to_vec(), b"one".to_vec()),
            (b"ctl\x12x.txt".to_vec(), b"two".to_vec()),
        ]
    );
}

#[test]
fn damaged_unicode_fields_name_the_member_by_its_legacy_name() {
    for (field, legacy, cp850) in [
        // Units 'a', 'b', NUL, 'c': UnRAR would call this "ab".
        (&b"ab\x81\0\0\0ab\0c"[..], &b"ab\x81"[..], "abü"),
        // Units NUL, 2, NUL: UnRAR would give it no name and skip it.
        (b"f\x81r.txt\0|\0\0\x02\0", b"f\x81r.txt", "für.txt"),
        // Unit 1: a control character, which no Windows name holds.
        (b"o\x81\0(\0\x01", b"o\x81", "oü"),
        // "P*|": three characters cannot give a 13-byte legacy name.
        (b"Sch\x81ler.txt\0\0\0P*|", b"Sch\x81ler.txt", "Schüler.txt"),
        // A copy command runs past the legacy name.
        (b"\x81ber.txt\0\0\xc0\x7f", b"\x81ber.txt", "über.txt"),
        // A command is cut short.
        (b"cut\x81.txt\0\0\x80A", b"cut\x81.txt", "cutü.txt"),
        // An unpaired surrogate.
        (b"h\x81\0\0\x80\0\xd8", b"h\x81", "hü"),
        // Nothing after the high byte.
        (b"none\x81.txt\0\0", b"none\x81.txt", "noneü.txt"),
    ] {
        let archive =
            ArchiveReader::read_owned(rar29(&[stored(field, FHD_UNICODE, b"data")])).unwrap();
        let member = archive.members().next().unwrap();
        assert_eq!(member.meta.name, legacy, "{field:?}");
        // The legacy bytes are of unknown encoding, so a caller may pick one.
        assert!(!member.name_is_unicode(), "{field:?}");
        assert_eq!(
            member
                .decoded_name(Some(LegacyNameEncoding::Cp850))
                .unwrap()
                .as_ref(),
            cp850.as_bytes(),
            "{field:?}"
        );
        assert_eq!(
            extract(&archive, None).unwrap(),
            [(legacy.to_vec(), b"data".to_vec())]
        );
    }
}

#[test]
fn well_formed_unicode_fields_still_name_the_member() {
    for (field, name) in [
        // Mode 0 units 'a', 'b', 'c'.
        (&b"x\0\0\0abc"[..], "abc"),
        // A copy of the legacy name with a correction.
        (b"ABC\0\x01\xc0\x81\x01", "\u{142}\u{143}\u{144}"),
        // Two full units under a Shift JIS legacy name of four bytes.
        (b"\x93\xfa\x96\x7b\0\0\xa0\xe5\x65\x2c\x67", "日本"),
    ] {
        let archive =
            ArchiveReader::read_owned(rar29(&[stored(field, FHD_UNICODE, b"data")])).unwrap();
        let member = archive.members().next().unwrap();
        assert_eq!(member.meta.name, name.as_bytes());
        assert!(member.name_is_unicode());
    }
}

#[test]
fn a_member_with_no_name_is_listed_and_its_data_still_read() {
    let archive = ArchiveReader::read_owned(rar29(&[
        stored(b"\0hidden.txt", 0, b"one"),
        stored(b"", 0, b"two"),
        stored(b"last.txt", 0, b"three"),
    ]))
    .unwrap();
    let names: Vec<_> = archive.members().map(|m| m.meta.name.clone()).collect();
    assert_eq!(names, [Vec::new(), Vec::new(), b"last.txt".to_vec()]);
    archive.test(None).unwrap();
    // The caller decides what to do with no name; the data is still there.
    assert_eq!(
        extract(&archive, None).unwrap(),
        [
            (Vec::new(), b"one".to_vec()),
            (Vec::new(), b"two".to_vec()),
            (b"last.txt".to_vec(), b"three".to_vec()),
        ]
    );
}

#[cfg(feature = "encryption")]
#[test]
fn an_encrypted_member_with_nothing_in_it_needs_no_password() {
    // As a damaged corpus archive has it: RAR 2.0 encryption, one cipher
    // block of packed data, no unpacked data, the CRC of nothing.
    let empty = Member {
        name: b"empty",
        flags: FHD_PASSWORD,
        data: &[0x5a; 16],
        unp_size: 0,
        crc: 0,
        unp_ver: 20,
        method: 0x33,
    };
    let archive = ArchiveReader::read_owned(rar29(&[empty])).unwrap();
    archive.test(None).unwrap();
    assert_eq!(
        extract(&archive, None).unwrap(),
        [(b"empty".to_vec(), Vec::new())]
    );

    // A CRC that is not the CRC of nothing still asks for the password.
    let claims_data = Member {
        name: b"claims",
        flags: FHD_PASSWORD,
        data: &[0x5a; 16],
        unp_size: 0,
        crc: 0x1234_5678,
        unp_ver: 20,
        method: 0x30,
    };
    let archive = ArchiveReader::read_owned(rar29(&[claims_data])).unwrap();
    assert_eq!(
        archive.test(None).unwrap_err().kind(),
        rars::ErrorKind::PasswordRequired
    );
}

#[cfg(all(feature = "write", feature = "encryption"))]
#[test]
fn written_encrypted_empty_members_test_without_a_password_before_rar5() {
    use rars::{ArchiveVersion, Builder};
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        for store in [true, false] {
            let archive = |data: &[u8]| {
                let mut builder = Builder::new(format)
                    .store(store)
                    .password(Some(b"secret".to_vec()));
                builder
                    .add_bytes(b"member".to_vec(), data.to_vec(), None, None)
                    .unwrap();
                ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
            };
            let empty = archive(b"").test(None);
            if format == ArchiveVersion::Rar50 {
                // RAR 5 checks the password itself, as UnRAR does.
                assert_eq!(
                    empty.unwrap_err().kind(),
                    rars::ErrorKind::PasswordRequired,
                    "{format:?} store={store}"
                );
            } else {
                empty.unwrap_or_else(|e| panic!("{format:?} store={store}: {e}"));
            }
            assert_eq!(
                archive(b"data").test(None).unwrap_err().kind(),
                rars::ErrorKind::PasswordRequired,
                "{format:?} store={store}"
            );
        }
    }
}
