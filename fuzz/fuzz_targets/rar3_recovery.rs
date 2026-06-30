#![no_main]

use libfuzzer_sys::fuzz_target;
use rars::rar15_40::{repair_rev3_volumes_to, Archive};
use rars::recovery::rar3::reconstruct_data_volumes;

const MAX_ARCHIVE_SIZE: usize = 512 * 1024;
const MAX_SHARD_SIZE: usize = 8 * 1024;
const MAX_DATA_VOLUMES: usize = 8;
const MAX_RECOVERY_VOLUMES: usize = 8;

fuzz_target!(|data: &[u8]| {
    let raw = &data[..data.len().min(MAX_ARCHIVE_SIZE)];
    if let Ok(archive) = Archive::parse(raw) {
        let _ = archive.protect_records().count();
        let _ = archive
            .new_subs()
            .filter(|sub| sub.kind == rars::rar15_40::NewSubKind::RecoveryRecord)
            .count();
        let _ = archive.repair_protect_head();
    }

    if raw.len() < 4 {
        return;
    }
    let data_count = 1 + usize::from(raw[0] % MAX_DATA_VOLUMES as u8);
    let recovery_count = 1 + usize::from(raw[1] % MAX_RECOVERY_VOLUMES as u8);
    let shard_len = 1 + (usize::from(u16::from_le_bytes([raw[2], raw[3]])) % MAX_SHARD_SIZE);
    let mut cursor = 4;

    let mut data_storage = Vec::with_capacity(data_count);
    for index in 0..data_count {
        if cursor >= raw.len() {
            data_storage.push(None);
            continue;
        }
        let present = raw[cursor] & 1 == 0;
        cursor += 1;
        if !present {
            data_storage.push(None);
            continue;
        }
        let available = raw.len().saturating_sub(cursor).min(shard_len);
        let len = if available == 0 {
            0
        } else {
            1 + (usize::from(raw[cursor - 1]) % available)
        };
        data_storage.push(Some(raw[cursor..cursor + len].to_vec()));
        cursor += len;
        if index + 1 == data_count {
            break;
        }
    }
    while data_storage.len() < data_count {
        data_storage.push(None);
    }
    if data_storage.iter().all(Option::is_some) {
        data_storage[usize::from(raw[0]) % data_count] = None;
    }

    let mut recovery_storage = Vec::new();
    for recovery_index in 0..recovery_count {
        if cursor >= raw.len() {
            break;
        }
        let available = raw.len().saturating_sub(cursor).min(shard_len);
        let len = if available == 0 {
            0
        } else {
            1 + (usize::from(raw[cursor]) % available)
        };
        recovery_storage.push((recovery_index, raw[cursor..cursor + len].to_vec()));
        cursor += len;
    }

    let data_refs: Vec<_> = data_storage.iter().map(|entry| entry.as_deref()).collect();
    let recovery_refs: Vec<_> = recovery_storage
        .iter()
        .map(|(index, bytes)| (*index, bytes.as_slice()))
        .collect();
    let _ = reconstruct_data_volumes(&data_refs, recovery_count, &recovery_refs);
    let _ = repair_rev3_volumes_to(&data_refs, recovery_count, &recovery_refs, |_, _| Ok(()));
});
