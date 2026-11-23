//! How much memory this process may use, for defaults that scale with it.

/// Memory this process may use, where the platform says so without a system
/// call: on Linux, physical memory or the process's cgroup limit, whichever is
/// smaller, so a container's limit holds rather than the host's total.
pub(crate) fn physical_memory() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let total = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|info| meminfo_total(&info));
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|groups| cgroup_memory_limit(&groups, |path| std::fs::read_to_string(path).ok()));
    match (total, cgroup) {
        (Some(total), Some(limit)) => Some(total.min(limit)),
        (total, limit) => total.or(limit),
    }
}

/// `MemTotal` from `/proc/meminfo`, in bytes.
fn meminfo_total(info: &str) -> Option<u64> {
    let kib = info
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    kib.checked_mul(1024)
}

/// The tightest memory limit on the cgroup `groups` (the text of
/// `/proc/self/cgroup`) names, reading control files through `read`.
///
/// cgroup v2 limits are checked from the process's own group up to the root,
/// since any ancestor's `memory.max` binds too. Without v2, the v1 memory
/// controller's `memory.limit_in_bytes` is read. Inside a container the
/// recorded path is often the host's, so the mount's root is tried as well.
fn cgroup_memory_limit(groups: &str, read: impl Fn(&str) -> Option<String>) -> Option<u64> {
    const ROOT: &str = "/sys/fs/cgroup";
    let tightest = |dirs: &mut dyn Iterator<Item = String>, file: &str| {
        dirs.filter_map(|dir| read(&format!("{dir}/{file}")))
            .filter_map(|text| cgroup_limit_value(&text))
            .min()
    };
    if let Some(path) = groups.lines().find_map(|line| line.strip_prefix("0::")) {
        let mut dirs = ancestors(path).map(|group| format!("{ROOT}{group}"));
        return tightest(&mut dirs, "memory.max");
    }
    let path = groups.lines().find_map(|line| {
        let (_, rest) = line.split_once(':')?;
        let (controllers, path) = rest.split_once(':')?;
        controllers
            .split(',')
            .any(|name| name == "memory")
            .then_some(path)
    })?;
    let mut dirs = [path, "/"]
        .into_iter()
        .map(|group| format!("{ROOT}/memory{}", group.trim_end_matches('/')));
    tightest(&mut dirs, "memory.limit_in_bytes")
}

/// `path` and each cgroup above it, the root last, each without a trailing `/`.
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    let path = path.trim().trim_end_matches('/');
    std::iter::successors(Some(path), |group| {
        (!group.is_empty()).then(|| group.rfind('/').map_or("", |at| &group[..at]))
    })
}

/// A cgroup memory limit file's value in bytes: `max` is no limit, and so is
/// v1's unlimited figure, a page-rounded `i64::MAX`.
fn cgroup_limit_value(text: &str) -> Option<u64> {
    let bytes = text.trim().parse::<u64>().ok()?;
    (bytes < (i64::MAX as u64 & !0xFFFF)).then_some(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_cgroup_limit_bounds_memory_like_physical_memory() {
        use super::*;
        use std::collections::HashMap;

        const GIB: u64 = 1024 * 1024 * 1024;
        let files = |entries: &[(&str, &str)]| {
            let map: HashMap<String, String> = entries
                .iter()
                .map(|(path, text)| (path.to_string(), text.to_string()))
                .collect();
            move |path: &str| map.get(path).cloned()
        };
        assert_eq!(
            meminfo_total("MemTotal:       32768 kB\nMemFree: 1 kB\n"),
            Some(32 * 1024 * 1024)
        );

        // A container: v2, its own group at the namespace root.
        let container = files(&[("/sys/fs/cgroup/memory.max", "2147483648\n")]);
        assert_eq!(cgroup_memory_limit("0::/\n", &container), Some(2 * GIB));
        // `max` and a missing file are no limit.
        let unlimited = files(&[("/sys/fs/cgroup/a/memory.max", "max\n")]);
        assert_eq!(cgroup_memory_limit("0::/a\n", &unlimited), None);
        assert_eq!(cgroup_memory_limit("0::/a\n", files(&[])), None);
        assert_eq!(cgroup_memory_limit("", files(&[])), None);
        // An ancestor's limit binds a group without one of its own.
        let nested = files(&[
            ("/sys/fs/cgroup/a/b/memory.max", "max\n"),
            ("/sys/fs/cgroup/a/memory.max", "4294967296\n"),
            ("/sys/fs/cgroup/memory.max", "garbage"),
        ]);
        assert_eq!(cgroup_memory_limit("0::/a/b\n", &nested), Some(4 * GIB));

        // v1, with the host's path recorded but only the mount root visible.
        let v1 = files(&[(
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            "1073741824\n",
        )]);
        let groups = "12:cpu,cpuacct:/docker/abc\n4:memory:/docker/abc\n";
        assert_eq!(cgroup_memory_limit(groups, &v1), Some(GIB));
        let v1_unlimited = files(&[(
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            "9223372036854771712\n",
        )]);
        assert_eq!(cgroup_memory_limit(groups, &v1_unlimited), None);
    }
}
