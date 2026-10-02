//! Identifies what kind of document a CFBF container actually is, from its root storage's CLSID
//! and, as a fallback/corroborating signal, its top-level stream names.
//!
//! CLSID matching is the primary signal because it is what the authoring application itself
//! wrote; stream names are the fallback because a CLSID can be absent (rare, but real-world
//! files do exist with a null root CLSID) or -- more usefully for forensic purposes -- can
//! *disagree* with the stream layout, which is itself a signal worth surfacing rather than
//! silently preferring one source over the other.
//!
//! Every CLSID below is a well-known, widely-documented ProgID class identifier (Word/Excel's
//! and the Windows Installer's are independently confirmed against this crate's own two local
//! fixtures in `tests/`). A CLSID this table does not recognize is not an error -- it is
//! [`OleFormat::Unknown`] carrying the raw CLSID, which is exactly the honest answer for a
//! format this crate has not been taught yet.

use crate::directory::DirectoryEntry;

/// What kind of OLE compound document this is, so far as this crate can tell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OleFormat {
    /// `Word.Document.8` -- Word 97-2003 (`.doc`, `.dot`).
    Word97,
    /// `Excel.Sheet.8` -- Excel 97-2003 (`.xls`, `.xlt`).
    Excel97,
    /// PowerPoint 97-2003 (`.ppt`, `.pot`, `.pps`).
    PowerPoint97,
    /// A Windows Installer package (`.msi`) or patch (`.msp`).
    Installer,
    /// An Outlook message (`.msg`).
    OutlookMessage,
    /// Recognized by neither CLSID nor stream-name heuristic.
    #[default]
    Unknown,
}

impl std::fmt::Display for OleFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OleFormat::Word97 => "word_document",
            OleFormat::Excel97 => "excel_workbook",
            OleFormat::PowerPoint97 => "powerpoint_presentation",
            OleFormat::Installer => "msi_package",
            OleFormat::OutlookMessage => "outlook_message",
            OleFormat::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Which signal, if any, [`FormatIdentity`] was actually resolved from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FormatEvidence {
    /// The root storage's CLSID matched a known class id.
    RootClsid,
    /// No (or an unrecognized) CLSID, but a top-level stream name matched a known layout.
    StreamName,
    /// Neither signal matched anything this crate recognizes.
    #[default]
    None,
}

/// The result of identifying a document's format: what it is, how confidently, and whether the
/// two signals actually agreed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FormatIdentity {
    pub format: OleFormat,
    pub evidence: FormatEvidence,
    /// The root CLSID this crate matched against known classes, as a canonical GUID string
    /// (`None` for a null root CLSID).
    pub clsid: Option<String>,
    /// `true` when the root CLSID and the stream-name heuristic independently point at
    /// *different* known formats -- a signal worth surfacing on its own (a mismatched or
    /// tampered CLSID, a document rebuilt from another format's streams), never silently
    /// resolved in one signal's favor.
    pub clsid_conflicts_with_streams: bool,
}

/// (CLSID bytes as stored on the wire, resolved format). Every entry independently verified
/// against a well-known ProgID's published CLSID.
const KNOWN_CLSIDS: &[([u8; 16], OleFormat)] = &[
    // Word.Document.8 -- {00020906-0000-0000-C000-000000000046}
    (
        [
            0x06, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ],
        OleFormat::Word97,
    ),
    // Excel.Sheet.8 -- {00020820-0000-0000-C000-000000000046}
    (
        [
            0x20, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ],
        OleFormat::Excel97,
    ),
    // PowerPoint 97 presentation -- {64818D10-4F9B-11CF-86EA-00AA00B929E8}
    (
        [
            0x10, 0x8D, 0x81, 0x64, 0x9B, 0x4F, 0xCF, 0x11, 0x86, 0xEA, 0x00, 0xAA, 0x00, 0xB9,
            0x29, 0xE8,
        ],
        OleFormat::PowerPoint97,
    ),
    // Windows Installer Package -- {000C1084-0000-0000-C000-000000000046}. Confirmed against
    // this crate's own MSI fixture in `tests/msi_fixture.rs`.
    (
        [
            0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ],
        OleFormat::Installer,
    ),
    // Outlook IPM.Note message -- {00020D0B-0000-0000-C000-000000000046}
    (
        [
            0x0B, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ],
        OleFormat::OutlookMessage,
    ),
];

/// Resolves [`OleFormat`] from the root storage entry's CLSID plus a list of this container's
/// top-level stream names (unqualified, i.e. the leaf name of each path with no `/` in it).
pub fn identify(root: &DirectoryEntry, top_level_streams: &[&str]) -> FormatIdentity {
    let from_clsid = KNOWN_CLSIDS
        .iter()
        .find(|(clsid, _)| *clsid == root.clsid)
        .map(|&(_, f)| f);
    let from_streams = identify_by_streams(top_level_streams);

    let (format, evidence) = match (from_clsid, from_streams) {
        (Some(f), _) => (f, FormatEvidence::RootClsid),
        (None, Some(f)) => (f, FormatEvidence::StreamName),
        (None, None) => (OleFormat::Unknown, FormatEvidence::None),
    };
    let clsid_conflicts_with_streams =
        matches!((from_clsid, from_streams), (Some(a), Some(b)) if a != b);

    FormatIdentity {
        format,
        evidence,
        clsid: root.clsid_string(),
        clsid_conflicts_with_streams,
    }
}

fn identify_by_streams(top_level_streams: &[&str]) -> Option<OleFormat> {
    // Streams carrying a [MS-CFB] 2.6.1 marker byte (0x01/0x05) still compare correctly here:
    // the marker is part of the name, and none of the streams matched below use one.
    if top_level_streams.contains(&"WordDocument") {
        Some(OleFormat::Word97)
    } else if top_level_streams
        .iter()
        .any(|&s| s == "Workbook" || s == "Book")
    {
        Some(OleFormat::Excel97)
    } else if top_level_streams.contains(&"PowerPoint Document") {
        Some(OleFormat::PowerPoint97)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::ObjectType;

    fn root_with_clsid(clsid: [u8; 16]) -> DirectoryEntry {
        DirectoryEntry {
            name: "Root Entry".to_string(),
            object_type: ObjectType::RootStorage,
            left_sibling_id: u32::MAX,
            right_sibling_id: u32::MAX,
            child_id: u32::MAX,
            clsid,
            start_sector: 0,
            stream_size: 0,
            created: None,
            modified: None,
        }
    }

    #[test]
    fn identifies_word_by_clsid() {
        let root = root_with_clsid(KNOWN_CLSIDS[0].0);
        let id = identify(&root, &[]);
        assert_eq!(id.format, OleFormat::Word97);
        assert_eq!(id.evidence, FormatEvidence::RootClsid);
        assert!(!id.clsid_conflicts_with_streams);
    }

    #[test]
    fn falls_back_to_stream_name_when_clsid_is_null() {
        let root = root_with_clsid([0u8; 16]);
        let id = identify(&root, &["WordDocument", "1Table"]);
        assert_eq!(id.format, OleFormat::Word97);
        assert_eq!(id.evidence, FormatEvidence::StreamName);
        assert!(id.clsid.is_none());
    }

    #[test]
    fn an_unrecognized_clsid_with_no_matching_streams_is_unknown() {
        let root = root_with_clsid([0xAB; 16]);
        let id = identify(&root, &["SomeStream"]);
        assert_eq!(id.format, OleFormat::Unknown);
        assert_eq!(id.evidence, FormatEvidence::None);
    }

    #[test]
    fn flags_a_clsid_that_disagrees_with_the_stream_layout() {
        // Excel CLSID, but a Word-shaped stream layout.
        let root = root_with_clsid(KNOWN_CLSIDS[1].0);
        let id = identify(&root, &["WordDocument"]);
        assert_eq!(
            id.format,
            OleFormat::Excel97,
            "CLSID wins when it matches a known class"
        );
        assert!(id.clsid_conflicts_with_streams);
    }

    #[test]
    fn identifies_the_msi_clsid() {
        let root = root_with_clsid(KNOWN_CLSIDS[3].0);
        let id = identify(&root, &[]);
        assert_eq!(id.format, OleFormat::Installer);
    }
}
