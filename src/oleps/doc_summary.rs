//! Projects a `PropertySection` from the `\x05DocumentSummaryInformation` stream ([MS-OLEPS]
//! 2.3 -- FMTID `{D5CDD502-2E9C-101B-9397-08002B2CF9AE}`) onto its well-known `PIDDSI_*` fields.
//!
//! `\x05DocumentSummaryInformation` can carry a *second* [`super::PropertySection`] (FMTID
//! `{D5CDD505-2E9C-101B-9397-08002B2CF9AE}`), the user-defined-properties section -- reachable
//! via [`super::PropertySection::user_defined_properties`] on whichever of
//! [`super::PropertySetStream::sections`] is not this one.

use super::PropertySection;

const PIDDSI_CATEGORY: u32 = 2;
const PIDDSI_PRESFORMAT: u32 = 3;
const PIDDSI_BYTECOUNT: u32 = 4;
const PIDDSI_LINECOUNT: u32 = 5;
const PIDDSI_PARCOUNT: u32 = 6;
const PIDDSI_SLIDECOUNT: u32 = 7;
const PIDDSI_NOTECOUNT: u32 = 8;
const PIDDSI_HIDDENCOUNT: u32 = 9;
const PIDDSI_MMCLIPCOUNT: u32 = 10;
const PIDDSI_SCALE: u32 = 11;
const PIDDSI_DOCPARTS: u32 = 13;
const PIDDSI_MANAGER: u32 = 14;
const PIDDSI_COMPANY: u32 = 15;
const PIDDSI_LINKSDIRTY: u32 = 16;
const PIDDSI_CCHWITHSPACES: u32 = 17;
const PIDDSI_SHAREDDOC: u32 = 19;
const PIDDSI_VERSION: u32 = 23;
const PIDDSI_CONTENTTYPE: u32 = 26;
const PIDDSI_CONTENTSTATUS: u32 = 27;
const PIDDSI_LANGUAGE: u32 = 28;
const PIDDSI_DOCVERSION: u32 = 29;

/// Document-authoring metadata from the `\x05DocumentSummaryInformation` stream's well-known
/// property section.
#[derive(Debug, Clone)]
pub struct DocumentSummaryInformation {
    pub category: Option<String>,
    pub presentation_format: Option<String>,
    pub byte_count: Option<u64>,
    pub line_count: Option<u64>,
    pub paragraph_count: Option<u64>,
    pub slide_count: Option<u64>,
    pub note_count: Option<u64>,
    pub hidden_slide_count: Option<u64>,
    pub multimedia_clip_count: Option<u64>,
    pub scale_crop: Option<bool>,
    /// `PIDDSI_DOCPARTS` -- worksheet names for a workbook, slide titles for a presentation.
    /// Free coverage of Excel/PowerPoint text this crate does not otherwise extract.
    pub doc_parts: Vec<String>,
    pub manager: Option<String>,
    pub company: Option<String>,
    pub links_dirty: Option<bool>,
    pub char_count_with_spaces: Option<u64>,
    /// Deprecated per [MS-OLEPS] (`PIDDSI_SHAREDDOC` "MUST be `false`"), kept for completeness
    /// and as an anomaly signal if a writer set it anyway.
    pub shared_doc: Option<bool>,
    pub version: Option<i32>,
    pub content_type: Option<String>,
    pub content_status: Option<String>,
    pub language: Option<String>,
    pub doc_version: Option<String>,
}

impl DocumentSummaryInformation {
    pub fn from_section(section: &PropertySection) -> Self {
        let doc_parts = match section.get(PIDDSI_DOCPARTS) {
            Some(super::variant::PropertyValue::Vector(values)) => {
                values.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
            }
            _ => Vec::new(),
        };
        Self {
            category: section.text(PIDDSI_CATEGORY),
            presentation_format: section.text(PIDDSI_PRESFORMAT),
            byte_count: section.u64(PIDDSI_BYTECOUNT),
            line_count: section.u64(PIDDSI_LINECOUNT),
            paragraph_count: section.u64(PIDDSI_PARCOUNT),
            slide_count: section.u64(PIDDSI_SLIDECOUNT),
            note_count: section.u64(PIDDSI_NOTECOUNT),
            hidden_slide_count: section.u64(PIDDSI_HIDDENCOUNT),
            multimedia_clip_count: section.u64(PIDDSI_MMCLIPCOUNT),
            scale_crop: section.bool(PIDDSI_SCALE),
            doc_parts,
            manager: section.text(PIDDSI_MANAGER),
            company: section.text(PIDDSI_COMPANY),
            links_dirty: section.bool(PIDDSI_LINKSDIRTY),
            char_count_with_spaces: section.u64(PIDDSI_CCHWITHSPACES),
            shared_doc: section.bool(PIDDSI_SHAREDDOC),
            version: section.i32(PIDDSI_VERSION),
            content_type: section.text(PIDDSI_CONTENTTYPE),
            content_status: section.text(PIDDSI_CONTENTSTATUS),
            language: section.text(PIDDSI_LANGUAGE),
            doc_version: section.text(PIDDSI_DOCVERSION),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oleps::codepage::CodePage;
    use crate::oleps::variant::{AnsiString, PropertyValue};
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
    fn extracts_doc_parts_from_a_vector_of_strings() {
        let vec_value = PropertyValue::Vector(vec![
            PropertyValue::AnsiStr(AnsiString::Ascii("Sheet1".to_string())),
            PropertyValue::AnsiStr(AnsiString::Ascii("Sheet2".to_string())),
        ]);
        let s = section(&[(PIDDSI_DOCPARTS, vec_value)]);
        let info = DocumentSummaryInformation::from_section(&s);
        assert_eq!(info.doc_parts, vec!["Sheet1".to_string(), "Sheet2".to_string()]);
    }

    #[test]
    fn absent_doc_parts_is_an_empty_vec_not_missing_data() {
        let s = section(&[]);
        let info = DocumentSummaryInformation::from_section(&s);
        assert!(info.doc_parts.is_empty());
    }

    #[test]
    fn shared_doc_deprecated_flag_still_surfaces_when_a_writer_set_it() {
        let s = section(&[(PIDDSI_SHAREDDOC, PropertyValue::Bool(true))]);
        let info = DocumentSummaryInformation::from_section(&s);
        assert_eq!(info.shared_doc, Some(true));
    }
}
