//! [`OleDocument`]: the typed document view built on top of the raw CFBF container -- property
//! sets, format identification, and (as later phases land) VBA macros, embedded objects, and
//! Word text.
//!
//! Deliberately an **owned** type with no lifetime borrowing its source: every accessor here
//! captures already-decoded, already-owned data at construction time via [`CfbStreams`], rather
//! than holding a reference back into an [`crate::ole::OleFile`]. That is what lets
//! `OleFile::document()` cache one behind a `OnceLock` on `OleFile` itself without a
//! self-referential struct.
//!
//! Every accessor here is infallible and best-effort by construction: a stream that is absent,
//! malformed, or fails to decode simply leaves the corresponding field `None`/empty and appends
//! a note to [`OleDocument::warnings`], rather than failing the whole build. A caller building a
//! pipeline record on top of this should never need to handle an `Err` from this layer.

use crate::directory::DirectoryEntry;
use crate::format::{self, FormatIdentity};
use crate::oleps::{self, DocumentSummaryInformation, MsiSummaryInformation, SummaryInformation, UserDefinedProperty};
use crate::source::CfbStreams;

/// [MS-CFB] 2.6.1's leading marker bytes on certain well-known stream names (e.g.
/// `"\x05SummaryInformation"`, `"\x01CompObj"`). Stripped for name comparison, since the marker
/// is an implementation detail of how the name is stored, not part of the name itself.
const NAME_MARKERS: [char; 2] = ['\u{1}', '\u{5}'];

fn strip_marker(name: &str) -> &str {
    name.trim_start_matches(NAME_MARKERS)
}

/// Finds a top-level stream by name, ignoring any [MS-CFB] 2.6.1 marker byte.
fn find_stream<'a>(top_level_streams: &[&'a str], want: &str) -> Option<&'a str> {
    top_level_streams.iter().copied().find(|&name| strip_marker(name) == want)
}

/// The typed document view over one parsed CFBF container.
#[derive(Debug, Clone, Default)]
pub struct OleDocument {
    format: FormatIdentity,
    summary_information: Option<SummaryInformation>,
    msi_summary_information: Option<MsiSummaryInformation>,
    document_summary_information: Option<DocumentSummaryInformation>,
    user_defined_properties: Vec<UserDefinedProperty>,
    encryption: crate::crypto::EncryptionState,
    warnings: Vec<String>,
}

impl OleDocument {
    /// Builds the document view. `root` is the CFBF container's root directory entry;
    /// `top_level_streams` is every stream name directly under the root (unqualified, no `/`).
    pub fn build(source: &impl CfbStreams, root: &DirectoryEntry, top_level_streams: &[&str]) -> Self {
        let mut warnings = Vec::new();
        let format = format::identify(root, top_level_streams);

        // Read the `\x05SummaryInformation` stream once and project it two ways (regular and
        // MSI-repurposed semantics) rather than reading and re-warning about it twice.
        let summary_info_stream =
            find_stream(top_level_streams, "SummaryInformation").and_then(|name| read_property_set(source, name, &mut warnings));
        let summary_information = summary_info_stream.as_ref().and_then(|s| s.sections.first()).map(SummaryInformation::from_section);
        let msi_summary_information = summary_info_stream.as_ref().and_then(|s| s.sections.first()).map(MsiSummaryInformation::from_section);

        let doc_summary_stream =
            find_stream(top_level_streams, "DocumentSummaryInformation").and_then(|name| read_property_set(source, name, &mut warnings));
        let document_summary_information = doc_summary_stream.as_ref().and_then(|s| s.sections.first()).map(DocumentSummaryInformation::from_section);
        let user_defined_properties =
            doc_summary_stream.as_ref().and_then(|s| s.sections.get(1)).map(|s| s.user_defined_properties()).unwrap_or_default();

        Self {
            format,
            summary_information,
            msi_summary_information,
            document_summary_information,
            user_defined_properties,
            encryption: crate::crypto::EncryptionState::default(),
            warnings,
        }
    }

    pub fn format(&self) -> &FormatIdentity {
        &self.format
    }

    /// Document-authoring metadata from `\x05SummaryInformation`, under its regular (non-MSI)
    /// interpretation. `None` when the stream is absent or unparseable, not when its
    /// properties happen to be empty.
    pub fn summary_information(&self) -> Option<&SummaryInformation> {
        self.summary_information.as_ref()
    }

    /// The same `\x05SummaryInformation` stream, projected under the Windows Installer's
    /// repurposed property semantics -- meaningful when [`Self::format`] is
    /// [`format::OleFormat::Installer`], present regardless in case a caller wants to check
    /// for itself.
    pub fn msi_summary_information(&self) -> Option<&MsiSummaryInformation> {
        self.msi_summary_information.as_ref()
    }

    pub fn document_summary_information(&self) -> Option<&DocumentSummaryInformation> {
        self.document_summary_information.as_ref()
    }

    /// Custom document properties from `\x05DocumentSummaryInformation`'s user-defined
    /// properties section, if the stream carried one.
    pub fn user_defined_properties(&self) -> &[UserDefinedProperty] {
        &self.user_defined_properties
    }

    pub fn encryption(&self) -> &crate::crypto::EncryptionState {
        &self.encryption
    }

    /// Non-fatal issues encountered while building this view (an unparseable property set, an
    /// unexpected section count, ...). Never silently dropped, but never fatal either -- see
    /// the module doc for why every accessor here stays infallible.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

fn read_property_set(source: &impl CfbStreams, name: &str, warnings: &mut Vec<String>) -> Option<oleps::PropertySetStream> {
    let bytes = match source.stream(name) {
        Ok(bytes) => bytes,
        Err(e) => {
            warnings.push(format!("could not read '{name}': {e}"));
            return None;
        }
    };
    match oleps::parse(&bytes) {
        Ok(stream) if stream.sections.is_empty() => {
            warnings.push(format!("'{name}' parsed with zero property sections"));
            None
        }
        Ok(stream) => Some(stream),
        Err(e) => {
            warnings.push(format!("could not parse '{name}' as a property set: {e}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::ObjectType;
    use crate::source::MapStreams;

    fn root_entry() -> DirectoryEntry {
        DirectoryEntry {
            name: "Root Entry".to_string(),
            object_type: ObjectType::RootStorage,
            left_sibling_id: u32::MAX,
            right_sibling_id: u32::MAX,
            child_id: u32::MAX,
            clsid: [0u8; 16],
            start_sector: 0,
            stream_size: 0,
            created: None,
            modified: None,
        }
    }

    /// Builds a minimal one-section `\x05SummaryInformation`-shaped stream with a single
    /// `PIDSI_TITLE` (id 2) property, reusing the same byte layout `oleps::mod`'s own tests do.
    fn summary_info_bytes(title: &str) -> Vec<u8> {
        let fmtid = [0u8; 16];
        let mut out = Vec::new();
        out.extend_from_slice(&0xFFFEu16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&fmtid);
        let offset0_pos = out.len();
        out.extend_from_slice(&0u32.to_le_bytes());
        let section_start = out.len() as u32;
        out[offset0_pos..offset0_pos + 4].copy_from_slice(&section_start.to_le_bytes());

        let mut section = Vec::new();
        section.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
        section.extend_from_slice(&1u32.to_le_bytes()); // 1 property
        let header_len = 8 + 8;
        section.extend_from_slice(&2u32.to_le_bytes()); // PIDSI_TITLE
        section.extend_from_slice(&(header_len as u32).to_le_bytes());
        let mut payload = title.as_bytes().to_vec();
        payload.push(0);
        section.extend_from_slice(&0x1Eu16.to_le_bytes()); // VT_LPSTR
        section.extend_from_slice(&0u16.to_le_bytes());
        section.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        section.extend_from_slice(&payload);
        let size = section.len() as u32;
        section[0..4].copy_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&section);
        out
    }

    #[test]
    fn builds_summary_information_from_the_well_known_stream() {
        let streams = MapStreams::new().with("\u{5}SummaryInformation", summary_info_bytes("Hello"));
        let doc = OleDocument::build(&streams, &root_entry(), &["\u{5}SummaryInformation"]);
        assert_eq!(doc.summary_information().and_then(|s| s.title.clone()), Some("Hello".to_string()));
        assert!(doc.warnings().is_empty());
    }

    #[test]
    fn missing_streams_yield_none_not_an_error() {
        let streams = MapStreams::new();
        let doc = OleDocument::build(&streams, &root_entry(), &[]);
        assert!(doc.summary_information().is_none());
        assert!(doc.document_summary_information().is_none());
        assert!(doc.user_defined_properties().is_empty());
        assert!(doc.warnings().is_empty(), "an absent stream is not a warning-worthy failure");
    }

    #[test]
    fn a_malformed_property_set_is_a_warning_not_a_panic_or_missing_document() {
        let streams = MapStreams::new().with("\u{5}SummaryInformation", vec![0x00, 0x00]); // too short to parse
        let doc = OleDocument::build(&streams, &root_entry(), &["\u{5}SummaryInformation"]);
        assert!(doc.summary_information().is_none());
        assert_eq!(doc.warnings().len(), 1);
    }

    #[test]
    fn encryption_defaults_to_not_checked_rather_than_claiming_clean() {
        let streams = MapStreams::new();
        let doc = OleDocument::build(&streams, &root_entry(), &[]);
        assert!(matches!(doc.encryption(), crate::crypto::EncryptionState::NotChecked { .. }));
    }
}
