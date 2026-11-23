/// What a caller is asking a writer to do, beyond the data it hands over.
///
/// Only choices that cannot be read off the data itself live here. Whether an
/// archive has a comment, a password, per-file comments or a recovery record is
/// decided by whether a comment, a password or a percentage was supplied, so
/// carrying separate flags for those only created a way for the two to
/// disagree, which is a bug the writer then had to check for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FeatureSet {
    /// Compress members against each other rather than independently.
    pub solid: bool,
    /// Encrypt the headers as well as the payloads, so names are not readable
    /// without the password.
    pub header_encryption: bool,
    /// Write an index so a reader can list the archive without walking every
    /// header.
    pub quick_open: bool,
    /// Store a BLAKE2sp hash of each member beside its CRC32, the hash rar's
    /// `-htb` writes. Readers then check the hash rather than the CRC32. RAR 5
    /// and later only.
    pub blake2sp: bool,
}

/// One writer feature, in the order a rejection prefers to report them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Feature {
    Solid,
    HeaderEncryption,
    QuickOpen,
    Blake2sp,
}

impl Feature {
    pub const ALL: [Self; 4] = [
        Self::Solid,
        Self::HeaderEncryption,
        Self::QuickOpen,
        Self::Blake2sp,
    ];

    /// How this feature is named when a writer has to refuse it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Solid => "solid compression",
            Self::HeaderEncryption => "header encryption",
            Self::QuickOpen => "a quick-open index",
            Self::Blake2sp => "BLAKE2sp file hashes",
        }
    }

    const fn get(self, set: FeatureSet) -> bool {
        match self {
            Self::Solid => set.solid,
            Self::HeaderEncryption => set.header_encryption,
            Self::QuickOpen => set.quick_open,
            Self::Blake2sp => set.blake2sp,
        }
    }
}

impl FeatureSet {
    pub const fn store_only() -> Self {
        Self {
            solid: false,
            header_encryption: false,
            quick_open: false,
            blake2sp: false,
        }
    }

    /// The first feature asked for here that `supported` does not offer.
    pub fn first_unsupported(self, supported: Self) -> Option<Feature> {
        Feature::ALL
            .into_iter()
            .find(|feature| feature.get(self) && !feature.get(supported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Destructuring exhaustively, so a new field is a compile error here
    /// rather than a silent hole in `Feature::ALL`.
    #[test]
    fn every_feature_field_has_an_entry_in_the_table() {
        let mut all = FeatureSet::store_only();
        let FeatureSet {
            solid,
            header_encryption,
            quick_open,
            blake2sp,
        } = &mut all;
        *solid = true;
        *header_encryption = true;
        *quick_open = true;
        *blake2sp = true;

        let reported: Vec<_> = Feature::ALL
            .into_iter()
            .filter(|feature| feature.get(all))
            .collect();
        assert_eq!(reported, Feature::ALL);
    }

    #[test]
    fn the_first_missing_feature_is_the_one_reported() {
        let asked = FeatureSet {
            solid: true,
            header_encryption: true,
            quick_open: true,
            blake2sp: true,
        };
        assert_eq!(
            asked.first_unsupported(FeatureSet::store_only()),
            Some(Feature::Solid)
        );
        assert_eq!(
            asked.first_unsupported(FeatureSet {
                solid: true,
                ..FeatureSet::store_only()
            }),
            Some(Feature::HeaderEncryption)
        );
        assert_eq!(asked.first_unsupported(asked), None);
    }
}
