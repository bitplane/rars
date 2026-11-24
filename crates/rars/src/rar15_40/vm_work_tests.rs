//! Custom RAR 3 filter programs share one instruction budget across an
//! extraction (issue #540).
use super::{Archive, FILE_HEAD, LONG_BLOCK, MAIN_HEAD};
use crate::codec::rar29::{encode_member_with_custom_filters, COUNTDOWN_VM_PROGRAM};
use crate::codec::rarvm::{VM_WORK_ARCHIVE_FLOOR, VM_WORK_MEMBER_FLOOR, VM_WORK_PER_BYTE};
use crate::crc32::crc32;
use crate::detect::RAR15_SIGNATURE;
use crate::{ArchiveMember, ArchiveReadOptions, Error, ExtractionErrorAction};
use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use std::sync::Mutex;

const MEMBERS: usize = 12;
const MEMBER_LEN: usize = 64;
/// Each member's one filter counts this far, two instructions a step.
const STEPS: u32 = 400_000;

fn with_header_crc(mut block: Vec<u8>) -> Vec<u8> {
    let crc = (crc32(&block[2..]) & 0xffff) as u16;
    block[..2].copy_from_slice(&crc.to_le_bytes());
    block
}

/// Non-solid members, each with one countdown filter over its first byte.
fn archive() -> (Vec<u8>, Vec<u8>) {
    let data: Vec<u8> = (0..MEMBER_LEN).map(|i| (i * 37 + 5) as u8).collect();
    let packed =
        encode_member_with_custom_filters(&data, COUNTDOWN_VM_PROGRAM, &[(0..1, STEPS)]).unwrap();
    let mut bytes = RAR15_SIGNATURE.to_vec();
    let mut main = vec![0, 0, MAIN_HEAD, 0, 0, 13, 0];
    main.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&with_header_crc(main));
    for index in 0..MEMBERS {
        let name = format!("m{index:02}");
        let mut header = vec![0, 0, FILE_HEAD];
        header.extend_from_slice(&LONG_BLOCK.to_le_bytes());
        header.extend_from_slice(&((32 + name.len()) as u16).to_le_bytes());
        header.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        header.extend_from_slice(&(data.len() as u32).to_le_bytes());
        header.push(2);
        header.extend_from_slice(&crc32(&data).to_le_bytes());
        header.extend_from_slice(&0x5a21_0000u32.to_le_bytes());
        header.extend_from_slice(&[29, 0x33]);
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0x20u32.to_le_bytes());
        header.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&with_header_crc(header));
        bytes.extend_from_slice(&packed);
    }
    (bytes, data)
}

struct Collect(Rc<RefCell<Vec<u8>>>);

impl Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

type Outputs = Vec<(Vec<u8>, Rc<RefCell<Vec<u8>>>)>;

/// Extracts every member, carrying on past failures, and returns what each
/// wrote and the members that failed, with why.
fn extract(archive: &Archive, parallel: bool, salvage: bool) -> (Outputs, Vec<(Vec<u8>, Error)>) {
    let failed = Mutex::new(Vec::new());
    let carry_on = |member: &ArchiveMember, error: &Error| {
        failed
            .lock()
            .unwrap()
            .push((member.meta.name.clone(), error.root_cause().clone()));
        Ok(ExtractionErrorAction::Continue)
    };
    let options = ArchiveReadOptions::new()
        .with_rar3_vm_programs(true)
        .with_member_error_handler(&carry_on)
        .with_salvage(salvage);
    let outputs = RefCell::new(Vec::new());
    let open = |meta: &super::ExtractedEntryMeta| -> crate::Result<Box<dyn Write>> {
        let data = Rc::new(RefCell::new(Vec::new()));
        outputs
            .borrow_mut()
            .push((meta.name.clone(), Rc::clone(&data)));
        Ok(Box::new(Collect(data)))
    };
    if parallel {
        archive.extract_to_parallel_buffered(options, open).unwrap();
    } else {
        archive.extract_to(options, open).unwrap();
    }
    (outputs.into_inner(), failed.into_inner().unwrap())
}

#[test]
fn custom_programs_share_one_budget_across_an_extraction() {
    let run = (2 * STEPS + 1) as u64;
    // Each run fits its own member's budget, and five fit the extraction's.
    assert!(run <= VM_WORK_MEMBER_FLOOR);
    let fit = (VM_WORK_ARCHIVE_FLOOR / (run - VM_WORK_PER_BYTE)) as usize;
    assert_eq!(fit, 5);

    let (bytes, data) = archive();
    let archive = Archive::parse(&bytes).unwrap();
    let budget = Error::Codec(crate::codec::Error::Rar3VmWorkLimitExceeded);
    for (parallel, salvage) in [(false, false), (true, false), (false, true)] {
        let case = format!("parallel {parallel}, salvage {salvage}");
        let (outputs, failed) = extract(&archive, parallel, salvage);
        // Parallel extraction opens only the members that decoded.
        let opened = if parallel {
            MEMBERS - failed.len()
        } else {
            MEMBERS
        };
        assert_eq!(outputs.len(), opened, "{case}");
        assert!(
            failed.iter().all(|(_, error)| *error == budget),
            "{case}: {failed:?}"
        );
        if parallel {
            // Workers take their runs' instructions from the budget before
            // running, so racing members can fail sooner, never later.
            assert!(failed.len() >= MEMBERS - fit, "{case}: {failed:?}");
        } else {
            let names: Vec<_> = failed.iter().map(|(name, _)| name.clone()).collect();
            let expected: Vec<_> = (fit..MEMBERS)
                .map(|index| format!("m{index:02}").into_bytes())
                .collect();
            assert_eq!(names, expected, "{case}");
        }
        for (name, output) in &outputs {
            let output = output.borrow();
            if salvage || !failed.iter().any(|(failed, _)| failed == name) {
                // Salvage skips the filter and delivers the member whole; the
                // countdown leaves its block as it was in any case.
                assert_eq!(*output, data, "{case}: {name:?}");
            }
        }
    }
    let error = Error::Codec(crate::codec::Error::Rar3VmWorkLimitExceeded);
    assert_eq!(error.kind(), crate::ErrorKind::InvalidArchive);
    assert!(error.to_string().contains("instruction budget"), "{error}");
}
