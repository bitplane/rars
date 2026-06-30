use crate::error::{Error, Result};
use crate::version::ArchiveVersion;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FeatureSet {
    pub solid: bool,
    pub file_encryption: bool,
    pub header_encryption: bool,
    pub archive_comment: bool,
    pub file_comment: bool,
    pub recovery_record: bool,
    pub rarvm_filters: bool,
    pub quick_open: bool,
    pub sfx: bool,
    pub authenticity_verification: bool,
}

impl FeatureSet {
    pub const fn store_only() -> Self {
        Self {
            solid: false,
            file_encryption: false,
            header_encryption: false,
            archive_comment: false,
            file_comment: false,
            recovery_record: false,
            rarvm_filters: false,
            quick_open: false,
            sfx: false,
            authenticity_verification: false,
        }
    }

    pub fn validate_for(self, version: ArchiveVersion) -> Result<()> {
        if version.is_rar13_family() {
            self.reject(version, self.header_encryption, "header_encryption")?;
            self.reject(version, self.recovery_record, "recovery_record")?;
            self.reject(version, self.rarvm_filters, "rarvm_filters")?;
            self.reject(version, self.quick_open, "quick_open")?;
        }

        Ok(())
    }

    fn reject(self, version: ArchiveVersion, enabled: bool, feature: &'static str) -> Result<()> {
        if enabled {
            Err(Error::UnsupportedFeature { version, feature })
        } else {
            Ok(())
        }
    }
}
