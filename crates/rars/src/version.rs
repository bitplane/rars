#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveFamily {
    Rar13,
    Rar15To40,
    Rar50Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveVersion {
    Rar13,
    Rar14,
    Rar15,
    Rar20,
    Rar29,
    Rar30,
    Rar40,
    Rar50,
    Rar70,
}

impl ArchiveVersion {
    pub const fn family(self) -> ArchiveFamily {
        match self {
            Self::Rar13 | Self::Rar14 => ArchiveFamily::Rar13,
            Self::Rar15 | Self::Rar20 | Self::Rar29 | Self::Rar30 | Self::Rar40 => {
                ArchiveFamily::Rar15To40
            }
            Self::Rar50 | Self::Rar70 => ArchiveFamily::Rar50Plus,
        }
    }

    pub const fn is_rar13_family(self) -> bool {
        matches!(self, Self::Rar13 | Self::Rar14)
    }

    /// Every version, so a caller can ask what each one supports without
    /// keeping its own list that drifts.
    pub const ALL: [Self; 9] = [
        Self::Rar13,
        Self::Rar14,
        Self::Rar15,
        Self::Rar20,
        Self::Rar29,
        Self::Rar30,
        Self::Rar40,
        Self::Rar50,
        Self::Rar70,
    ];

    /// The spelling used by the `--format` argument, and by every message a
    /// user reads. It is the only spelling they can type back into the tool.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rar13 => "rar13",
            Self::Rar14 => "rar14",
            Self::Rar15 => "rar15",
            Self::Rar20 => "rar20",
            Self::Rar29 => "rar29",
            Self::Rar30 => "rar30",
            Self::Rar40 => "rar40",
            Self::Rar50 => "rar50",
            Self::Rar70 => "rar70",
        }
    }
}

impl std::fmt::Display for ArchiveVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_versions_to_archive_families() {
        let cases = [
            (ArchiveVersion::Rar13, ArchiveFamily::Rar13),
            (ArchiveVersion::Rar14, ArchiveFamily::Rar13),
            (ArchiveVersion::Rar15, ArchiveFamily::Rar15To40),
            (ArchiveVersion::Rar20, ArchiveFamily::Rar15To40),
            (ArchiveVersion::Rar29, ArchiveFamily::Rar15To40),
            (ArchiveVersion::Rar30, ArchiveFamily::Rar15To40),
            (ArchiveVersion::Rar40, ArchiveFamily::Rar15To40),
            (ArchiveVersion::Rar50, ArchiveFamily::Rar50Plus),
            (ArchiveVersion::Rar70, ArchiveFamily::Rar50Plus),
        ];

        for (version, family) in cases {
            assert_eq!(version.family(), family);
        }
    }

    #[test]
    fn identifies_rar13_family_versions() {
        let cases = [
            (ArchiveVersion::Rar13, true),
            (ArchiveVersion::Rar14, true),
            (ArchiveVersion::Rar15, false),
            (ArchiveVersion::Rar20, false),
            (ArchiveVersion::Rar29, false),
            (ArchiveVersion::Rar30, false),
            (ArchiveVersion::Rar40, false),
            (ArchiveVersion::Rar50, false),
            (ArchiveVersion::Rar70, false),
        ];

        for (version, expected) in cases {
            assert_eq!(version.is_rar13_family(), expected);
        }
    }
}
