//! An independent consumer exercising parsing and sequential decoding.

use rars::ArchiveReader;
use std::io;

fn main() -> rars::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .expect("usage: rars-reader-consumer ARCHIVE");
    let input = std::fs::read(path)?;
    let archive = ArchiveReader::read(&input)?;
    archive.extract_to(None, |_| Ok(Box::new(io::sink())))?;
    Ok(())
}
