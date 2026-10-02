//! Projects a `PropertySection` from the `\x05SummaryInformation` stream ([MS-OLEPS] 2.2 --
//! FMTID `{F29F85E0-4FF9-1068-AB91-08002B27B3D9}`) onto its well-known `PIDSI_*` fields.
//!
//! An MSI installer's own `SummaryInformation` stream reuses this exact same container and
//! FMTID, but repurposes several property ids with installer-specific meanings (per the
//! Windows Installer SDK's "Summary Information Stream Property Set" reference) -- see
//! [`MsiSummaryInformation`], a second projection over the same [`PropertySection`].

use super::PropertySection;

const PIDSI_TITLE: u32 = 2;
const PIDSI_SUBJECT: u32 = 3;
const PIDSI_AUTHOR: u32 = 4;
const PIDSI_KEYWORDS: u32 = 5;
const PIDSI_COMMENTS: u32 = 6;
const PIDSI_TEMPLATE: u32 = 7;
const PIDSI_LASTAUTHOR: u32 = 8;
const PIDSI_REVNUMBER: u32 = 9;
const PIDSI_EDITTIME: u32 = 10;
const PIDSI_LASTPRINTED: u32 = 11;
const PIDSI_CREATE_DTM: u32 = 12;
const PIDSI_LASTSAVE_DTM: u32 = 13;
const PIDSI_PAGECOUNT: u32 = 14;
const PIDSI_WORDCOUNT: u32 = 15;
const PIDSI_CHARCOUNT: u32 = 16;
const PIDSI_APPNAME: u32 = 18;
const PIDSI_SECURITY: u32 = 19;

const HUNDRED_NS_PER_SECOND: u64 = 10_000_000;

/// Document-authoring metadata from a regular (non-MSI) `\x05SummaryInformation` stream.
#[derive(Debug, Clone)]
pub struct SummaryInformation {
    pub title: Option<String>,
    pub subject: Option<String>,
    pub author: Option<String>,
    pub keywords: Option<String>,
    pub comments: Option<String>,
    pub template: Option<String>,
    pub last_saved_by: Option<String>,
    pub revision_number: Option<String>,
    /// Total editing time, in seconds. `PIDSI_EDITTIME` is a `VT_FILETIME` on the wire but
    /// encodes a *duration*, not an instant -- deliberately not exposed as a
    /// `ForensicTimestamp`, which would misrepresent it as a point in time.
    pub total_edit_time_seconds: Option<u64>,
    pub last_printed: Option<forensic_rs::utils::time::ForensicTimestamp>,
    pub created: Option<forensic_rs::utils::time::ForensicTimestamp>,
    pub last_saved: Option<forensic_rs::utils::time::ForensicTimestamp>,
    pub page_count: Option<u64>,
    pub word_count: Option<u64>,
    pub char_count: Option<u64>,
    pub application_name: Option<String>,
    pub security: Option<DocSecurity>,
}

impl SummaryInformation {
    pub fn from_section(section: &PropertySection) -> Self {
        Self {
            title: section.text(PIDSI_TITLE),
            subject: section.text(PIDSI_SUBJECT),
            author: section.text(PIDSI_AUTHOR),
            keywords: section.text(PIDSI_KEYWORDS),
            comments: section.text(PIDSI_COMMENTS),
            template: section.text(PIDSI_TEMPLATE),
            last_saved_by: section.text(PIDSI_LASTAUTHOR),
            revision_number: section.text(PIDSI_REVNUMBER),
            total_edit_time_seconds: section
                .filetime_raw(PIDSI_EDITTIME)
                .map(|t| t / HUNDRED_NS_PER_SECOND),
            last_printed: section.filetime(PIDSI_LASTPRINTED),
            created: section.filetime(PIDSI_CREATE_DTM),
            last_saved: section.filetime(PIDSI_LASTSAVE_DTM),
            page_count: section.u64(PIDSI_PAGECOUNT),
            word_count: section.u64(PIDSI_WORDCOUNT),
            char_count: section.u64(PIDSI_CHARCOUNT),
            application_name: section.text(PIDSI_APPNAME),
            security: section
                .i32(PIDSI_SECURITY)
                .map(|bits| DocSecurity::from_bits(bits as u32)),
        }
    }
}

/// `PIDSI_SECURITY` ([MS-OLEPS] 2.2), a bitmask -- hand-rolled rather than pulling in a
/// `bitflags` dependency, matching `forensic-rs`'s own `FileAttributes` idiom.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DocSecurity(u32);

impl DocSecurity {
    pub const PASSWORD_PROTECTED: Self = DocSecurity(1 << 0);
    pub const READ_ONLY_RECOMMENDED: Self = DocSecurity(1 << 1);
    pub const READ_ONLY_ENFORCED: Self = DocSecurity(1 << 2);
    pub const LOCKED_FOR_ANNOTATIONS: Self = DocSecurity(1 << 3);

    pub fn from_bits(bits: u32) -> Self {
        DocSecurity(bits)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Property projection for an MSI's own `SummaryInformation` stream, which reuses
/// `\x05SummaryInformation`'s FMTID and container but repurposes several `PIDSI_*` ids with
/// installer-specific meanings, per the Windows Installer SDK.
#[derive(Debug, Clone)]
pub struct MsiSummaryInformation {
    pub title: Option<String>,
    /// `PIDSI_SUBJECT` -- the product name being installed.
    pub subject: Option<String>,
    /// `PIDSI_AUTHOR` -- the manufacturer.
    pub author: Option<String>,
    pub keywords: Option<String>,
    pub comments: Option<String>,
    /// `PIDSI_TEMPLATE` -- `"<platform>;<language id>"` (e.g. `"x64;1033"`), not a document
    /// template.
    pub platform_and_language: Option<String>,
    /// `PIDSI_LASTAUTHOR` -- the package code GUID.
    pub package_code: Option<String>,
    /// `PIDSI_REVNUMBER` -- `"{ProductCode}<PackageCode>;<UpgradeCode>"` in the SDK's own
    /// packed encoding; kept verbatim rather than parsed apart.
    pub revision_number: Option<String>,
    pub created: Option<forensic_rs::utils::time::ForensicTimestamp>,
    pub last_saved: Option<forensic_rs::utils::time::ForensicTimestamp>,
    /// `PIDSI_PAGECOUNT` -- the minimum Windows Installer engine version required, times 100
    /// (e.g. `200` means engine version 2.0).
    pub minimum_installer_version: Option<u64>,
    /// `PIDSI_WORDCOUNT` -- a bitfield of source/compression flags for the package, not a word
    /// count.
    pub word_count_flags: Option<u64>,
    pub application_name: Option<String>,
    pub security: Option<DocSecurity>,
}

impl MsiSummaryInformation {
    pub fn from_section(section: &PropertySection) -> Self {
        Self {
            title: section.text(PIDSI_TITLE),
            subject: section.text(PIDSI_SUBJECT),
            author: section.text(PIDSI_AUTHOR),
            keywords: section.text(PIDSI_KEYWORDS),
            comments: section.text(PIDSI_COMMENTS),
            platform_and_language: section.text(PIDSI_TEMPLATE),
            package_code: section.text(PIDSI_LASTAUTHOR),
            revision_number: section.text(PIDSI_REVNUMBER),
            created: section.filetime(PIDSI_CREATE_DTM),
            last_saved: section.filetime(PIDSI_LASTSAVE_DTM),
            minimum_installer_version: section.u64(PIDSI_PAGECOUNT),
            word_count_flags: section.u64(PIDSI_WORDCOUNT),
            application_name: section.text(PIDSI_APPNAME),
            security: section
                .i32(PIDSI_SECURITY)
                .map(|bits| DocSecurity::from_bits(bits as u32)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oleps::codepage::CodePage;
    use crate::oleps::variant::PropertyValue;
    use std::collections::BTreeMap;

    fn section(props: &[(u32, PropertyValue)]) -> PropertySection {
        PropertySection {
            fmtid: [0u8; 16],
            code_page: CodePage::Known(1252),
            properties: props.iter().cloned().collect::<BTreeMap<_, _>>(),
            dictionary: BTreeMap::new(),
        }
    }

    #[test]
    fn total_edit_time_is_exposed_as_a_duration_not_a_timestamp() {
        // 600,000,000 ticks of 100ns = 60 seconds.
        let s = section(&[(
            PIDSI_EDITTIME,
            PropertyValue::FileTime {
                raw: 600_000_000,
                timestamp: None,
            },
        )]);
        let info = SummaryInformation::from_section(&s);
        assert_eq!(info.total_edit_time_seconds, Some(60));
    }

    #[test]
    fn an_absent_property_is_none_not_a_default() {
        let s = section(&[]);
        let info = SummaryInformation::from_section(&s);
        assert!(info.author.is_none());
        assert!(info.created.is_none());
        assert!(info.security.is_none());
    }

    #[test]
    fn summary_and_msi_projections_disagree_on_pid_14_by_design() {
        let s = section(&[(PIDSI_PAGECOUNT, PropertyValue::I4(200))]);
        assert_eq!(SummaryInformation::from_section(&s).page_count, Some(200));
        assert_eq!(
            MsiSummaryInformation::from_section(&s).minimum_installer_version,
            Some(200)
        );
    }
}
