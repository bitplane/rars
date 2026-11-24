use super::*;
use crate::ArchiveVersion;
use std::cell::RefCell;
use std::rc::Rc;

type Files = Vec<(Vec<u8>, Vec<u8>)>;
type Outputs = Rc<RefCell<Files>>;
type Extracted = (Files, Option<String>, usize);

struct Collect(Outputs);

impl Write for Collect {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut outputs = self.0.borrow_mut();
        outputs.last_mut().unwrap().1.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn members() -> Files {
    let mut word = 0x2468_ace1u32;
    let mut next = || {
        word ^= word << 13;
        word ^= word >> 17;
        word ^= word << 5;
        word
    };
    let words: [&[u8]; 6] = [b"solid ", b"member ", b"ahead ", b"table ", b"the ", b"of "];
    (0..48)
        .map(|index| {
            let len = 200 + next() as usize % 3_000;
            let mut data = Vec::with_capacity(len + 8);
            while data.len() < len {
                let draw = next();
                if index % 7 == 3 || draw >> 29 == 0 {
                    data.push(draw as u8);
                } else {
                    data.extend_from_slice(words[draw as usize % words.len()]);
                }
            }
            data.truncate(len);
            (format!("dir/member-{index:02}.txt").into_bytes(), data)
        })
        .collect()
}

fn builder(members: &[(Vec<u8>, Vec<u8>)]) -> crate::Builder {
    let mut builder = crate::Builder::new(ArchiveVersion::Rar50)
        .store(false)
        .solid(true)
        .compression_level(Some(3));
    for (name, data) in members {
        builder
            .add_bytes(name.clone(), data.clone(), None, None)
            .unwrap();
    }
    builder
}

fn options(workers: usize) -> crate::ArchiveReadOptions<'static> {
    crate::ArchiveReadOptions::new()
        .with_rar50_decode_workers(workers)
        .with_rar50_buffered_decode_limit(MEMBER_AHEAD_LIMIT)
}

const MEMBER_AHEAD_LIMIT: u64 = 1 << 20;

fn extract(
    extract: impl FnOnce(
        crate::ArchiveReadOptions<'static>,
        &mut dyn FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    ) -> Result<()>,
    workers: usize,
) -> Extracted {
    let outputs = Outputs::default();
    let sink = Rc::clone(&outputs);
    let claims = solid_ahead::claims();
    let result = extract(options(workers), &mut |meta| {
        sink.borrow_mut().push((meta.name.clone(), Vec::new()));
        Ok(Box::new(Collect(Rc::clone(&sink))))
    });
    let claimed = solid_ahead::claims() - claims;
    let outputs = outputs.take();
    (
        outputs,
        result.err().map(|error| error.to_string()),
        claimed,
    )
}

fn assert_ahead_matches_serial(
    run: impl Fn(
        crate::ArchiveReadOptions<'static>,
        &mut dyn FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    ) -> Result<()>,
) -> Extracted {
    let (outputs, error, claimed) = extract(&run, 0);
    assert_eq!(claimed, 0);
    let mut ahead_claims = 0;
    for workers in [1, 4] {
        let ahead = extract(&run, workers);
        assert_eq!(
            (&ahead.0, &ahead.1),
            (&outputs, &error),
            "workers={workers}"
        );
        ahead_claims = ahead.2;
    }
    (outputs, error, ahead_claims)
}

#[test]
fn a_solid_chain_extracts_ahead_as_it_does_serially() {
    let members = members();
    let archive = Archive::parse_owned(builder(&members).to_bytes().unwrap()).unwrap();
    let (outputs, error, claimed) =
        assert_ahead_matches_serial(|options, open| archive.extract_to(options, |meta| open(meta)));
    assert_eq!(error, None);
    let files: Vec<_> = outputs
        .into_iter()
        .filter(|(name, _)| name != b"dir")
        .collect();
    assert_eq!(files, members);
    assert!(claimed >= members.len() - 1, "claimed {claimed}");
}

#[test]
fn a_damaged_member_stops_a_chain_ahead_where_it_stops_serially() {
    let members = members();
    let bytes = builder(&members).to_bytes().unwrap();
    let parsed = Archive::parse_owned(bytes.clone()).unwrap();
    let ranges: Vec<_> = parsed
        .files()
        .filter(|file| !file.is_directory())
        .map(|file| file.block.data_range.clone())
        .collect();
    let mut failed = 0;
    for range in ranges.iter().skip(5).step_by(9) {
        for at in [range.start, range.start + range.len() / 2, range.end - 1] {
            let mut damaged = bytes.clone();
            damaged[at] ^= 0x10;
            let archive = Archive::parse_owned(damaged).unwrap();
            let (_, error, _) = assert_ahead_matches_serial(|options, open| {
                archive.extract_to(options, |meta| open(meta))
            });
            failed += usize::from(error.is_some());
        }
    }
    assert!(failed > 10, "failed {failed}");
}

#[test]
fn a_solid_chain_across_volumes_extracts_ahead_as_it_does_serially() {
    let members = members();
    let volumes: Vec<_> = builder(&members)
        .volume_size(Some(4 * 1024))
        .build_volumes(None)
        .unwrap()
        .into_iter()
        .map(|bytes| Archive::parse_owned(bytes).unwrap())
        .collect();
    assert!(volumes.len() > 3);
    let (outputs, error, claimed) = assert_ahead_matches_serial(|options, open| {
        extract_volumes_to(&volumes, options, |meta| open(meta))
    });
    assert_eq!(error, None);
    let files: Vec<_> = outputs
        .into_iter()
        .filter(|(name, _)| name != b"dir")
        .collect();
    assert_eq!(files, members);
    assert!(claimed > members.len() / 2, "claimed {claimed}");
}

#[test]
#[cfg(feature = "encryption")]
fn an_encrypted_solid_chain_extracts_ahead_as_it_does_serially() {
    let members = members();
    let bytes = builder(&members)
        .password(Some(b"ahead".to_vec()))
        .to_bytes()
        .unwrap();
    let archive = Archive::parse_owned(bytes).unwrap();
    let (outputs, error, claimed) = assert_ahead_matches_serial(|mut options, open| {
        options.password = Some(b"ahead");
        archive.extract_to(options, |meta| open(meta))
    });
    assert_eq!(error, None);
    let files: Vec<_> = outputs
        .into_iter()
        .filter(|(name, _)| name != b"dir")
        .collect();
    assert_eq!(files, members);
    assert!(claimed >= members.len() - 1, "claimed {claimed}");
}
