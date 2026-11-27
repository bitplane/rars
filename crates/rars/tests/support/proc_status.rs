//! Reads the process's own memory figures on Linux.

#![allow(dead_code)]

/// One field of `/proc/self/status`, such as `VmHWM:`, in bytes.
pub fn status(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status
        .lines()
        .find(|line| line.starts_with(field))
        .unwrap_or_else(|| panic!("no {field} in /proc/self/status"));
    let kib: u64 = line[field.len()..]
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .unwrap();
    kib * 1024
}
