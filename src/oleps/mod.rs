//! [MS-OLEPS] "Object Linking and Embedding (OLE) Property Set Data Structures" -- the format
//! shared by the `\x05SummaryInformation` and `\x05DocumentSummaryInformation` streams (and,
//! with different property semantics, an MSI's own `SummaryInformation` stream).
//!
//! Layered as: this module parses the container (`PropertySetStream` -> one or two
//! `PropertySection`s, each a property-id-to-value map plus an optional name dictionary) with
//! no knowledge of what any property *means*; [`summary`] and [`doc_summary`] then project a
//! parsed section onto the well-known `PIDSI_*`/`PIDDSI_*` fields.
//!
//! Every property is addressed by an **absolute offset**, independently of every other property
//! ([MS-OLEPS] 2.14's offset table). That is what lets one malformed or unknown-type property
//! be skipped without corrupting the section's other, perfectly valid properties -- there is no
//! sequential "consume N bytes and hope the next property starts where expected" step anywhere
//! in this parser.

pub mod codepage;
pub mod doc_summary;
pub mod summary;
pub mod variant;

use std::collections::BTreeMap;

use forensic_rs::prelude::*;
use forensic_rs::{ensure_buffer_range, ensure_format};

use codepage::CodePage;
use variant::{AnsiString, PropertyValue, read_typed_value};

pub use doc_summary::DocumentSummaryInformation;
pub use summary::{DocSecurity, MsiSummaryInformation, SummaryInformation};

/// A fully parsed `\x05SummaryInformation`/`\x05DocumentSummaryInformation`-shaped stream: one
/// or two property sections, in the order the stream's own header declares them.
#[derive(Debug, Clone)]
pub struct PropertySetStream {
    pub sections: Vec<PropertySection>,
}

/// One `PropertySet` ([MS-OLEPS] 2.14): a property-id-keyed map of decoded values, this
/// section's own declared code page, and (when present) the name dictionary for its
/// user-defined properties ([MS-OLEPS] 2.17, property id 0 -- excluded from `properties`
/// itself, since it names properties rather than being one).
#[derive(Debug, Clone)]
pub struct PropertySection {
    pub fmtid: [u8; 16],
    pub code_page: CodePage,
    pub properties: BTreeMap<u32, PropertyValue>,
    pub dictionary: BTreeMap<u32, String>,
}

/// One user-defined property: its raw id, its name if the dictionary resolved one, and its
/// decoded value.
#[derive(Debug, Clone)]
pub struct UserDefinedProperty {
    pub id: u32,
    pub name: Option<String>,
    pub value: PropertyValue,
}

impl PropertySection {
    pub fn get(&self, id: u32) -> Option<&PropertyValue> {
        self.properties.get(&id)
    }

    pub fn text(&self, id: u32) -> Option<String> {
        self.get(id)
            .and_then(PropertyValue::as_str)
            .map(str::to_string)
    }

    pub fn i32(&self, id: u32) -> Option<i32> {
        self.get(id).and_then(PropertyValue::as_i32)
    }

    pub fn u64(&self, id: u32) -> Option<u64> {
        self.get(id).and_then(PropertyValue::as_u64)
    }

    pub fn filetime(&self, id: u32) -> Option<ForensicTimestamp> {
        self.get(id).and_then(PropertyValue::as_filetime)
    }

    /// The raw 100ns tick count of a `VT_FILETIME` property, for a field that represents a
    /// *duration* (e.g. `PIDSI_EDITTIME`) rather than an absolute instant.
    pub fn filetime_raw(&self, id: u32) -> Option<u64> {
        self.get(id).and_then(PropertyValue::as_filetime_raw)
    }

    pub fn bool(&self, id: u32) -> Option<bool> {
        self.get(id).and_then(PropertyValue::as_bool)
    }

    /// Every property in this section (excluding `PID_CODEPAGE`, id 1, and the dictionary
    /// itself, id 0), paired with its dictionary-resolved name when one exists. Meant for the
    /// user-defined-properties section of a `DocumentSummaryInformation` stream, but works on
    /// any section.
    pub fn user_defined_properties(&self) -> Vec<UserDefinedProperty> {
        self.properties
            .iter()
            .filter(|&(&id, _)| id != 1)
            .map(|(&id, value)| UserDefinedProperty {
                id,
                name: self.dictionary.get(&id).cloned(),
                value: value.clone(),
            })
            .collect()
    }
}

const BYTE_ORDER_MARKER: u16 = 0xFFFE;

/// Parses a `PropertySetStream`'s raw bytes ([MS-OLEPS] 2.13).
pub fn parse(data: &[u8]) -> ForensicResult<PropertySetStream> {
    let mut reader = ByteReader::new(data);
    let byte_order = reader.read_u16_le()?;
    ensure_format!(
        byte_order == BYTE_ORDER_MARKER,
        "ole_property_set",
        "invalid property set byte order marker"
    );
    let _version = reader.read_u16_le()?;
    let _system_identifier = reader.read_u32_le()?;
    let _clsid = reader.read_fixed::<16>()?;
    let num_sets = reader.read_u32_le()?;
    ensure_format!(
        num_sets == 1 || num_sets == 2,
        "ole_property_set",
        "NumPropertySets must be 1 or 2"
    );

    let mut headers = Vec::with_capacity(num_sets as usize);
    for _ in 0..num_sets {
        let fmtid = reader.read_fixed::<16>()?;
        let offset = reader.read_u32_le()?;
        headers.push((fmtid, offset));
    }

    let mut sections = Vec::with_capacity(headers.len());
    for (fmtid, offset) in headers {
        sections.push(parse_section(data, fmtid, offset as usize)?);
    }
    Ok(PropertySetStream { sections })
}

fn parse_section(
    data: &[u8],
    fmtid: [u8; 16],
    section_start: usize,
) -> ForensicResult<PropertySection> {
    ensure_buffer_range!(data, section_start, section_start + 8);
    let mut header = ByteReader::new(&data[section_start..]);
    let _size = header.read_u32_le()?;
    let declared_count = header.read_u32_le()?;
    // A corrupt/adversarial count is bounded by what could possibly fit (8 bytes per
    // id/offset pair) rather than trusted outright.
    let count = declared_count.min((data.len().saturating_sub(section_start) / 8) as u32);

    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let id = header.read_u32_le()?;
        let rel_offset = header.read_u32_le()?;
        entries.push((id, rel_offset));
    }

    let code_page = entries
        .iter()
        .find(|&&(id, _)| id == 1)
        .and_then(|&(_, rel)| read_code_page(data, section_start, rel))
        .unwrap_or(CodePage::Absent);

    let dictionary = entries
        .iter()
        .find(|&&(id, _)| id == 0)
        .and_then(|&(_, rel)| section_start.checked_add(rel as usize))
        .and_then(|abs| parse_dictionary(data, abs, code_page).ok())
        .unwrap_or_default();

    let mut properties = BTreeMap::new();
    for &(id, rel_offset) in &entries {
        if id == 0 {
            continue; // the dictionary names properties; it is not one itself.
        }
        let Some(abs) = section_start.checked_add(rel_offset as usize) else {
            continue;
        };
        let mut value_reader = ByteReader::new(data);
        if value_reader.seek_to(abs).is_err() {
            continue;
        }
        // One malformed/unreachable property must not cost the section every other property --
        // each is independently addressed, so skip and move on rather than aborting the parse.
        if let Ok(value) = read_typed_value(&mut value_reader, code_page) {
            properties.insert(id, value);
        }
    }

    Ok(PropertySection {
        fmtid,
        code_page,
        properties,
        dictionary,
    })
}

fn read_code_page(data: &[u8], section_start: usize, rel_offset: u32) -> Option<CodePage> {
    let abs = section_start.checked_add(rel_offset as usize)?;
    let mut reader = ByteReader::new(data);
    reader.seek_to(abs).ok()?;
    match read_typed_value(&mut reader, CodePage::Absent).ok()? {
        PropertyValue::I2(v) => Some(CodePage::from_raw(v)),
        _ => None,
    }
}

/// [MS-OLEPS] 2.17 `Dictionary`: a `Count`-prefixed list of `(PropertyIdentifier, Length, Name)`
/// entries, each padded to a 4-byte boundary. Unicode-keyed (`CodePage::Unsupported(1200)`)
/// dictionaries are out of scope and refused outright rather than misparsed.
fn parse_dictionary(
    data: &[u8],
    start: usize,
    code_page: CodePage,
) -> ForensicResult<BTreeMap<u32, String>> {
    if matches!(code_page, CodePage::Unsupported(1200)) {
        return Err(ForensicError::missing_data(
            "ole_property_dictionary",
            CompactString::from("unicode-keyed property dictionaries are not supported"),
        ));
    }
    let mut reader = ByteReader::new(data);
    reader.seek_to(start)?;
    let declared_count = reader.read_u32_le()?;
    let count = declared_count.min((reader.remaining() / 8) as u32 + 1);

    let mut map = BTreeMap::new();
    for _ in 0..count {
        let id = reader.read_u32_le()?;
        let length = reader.read_u32_le()? as usize;
        let bytes = reader.read_bytes(length)?;
        if let Some(name) = AnsiString::decode(bytes, code_page).as_str() {
            map.insert(id, name.to_string());
        }
        let entry_len = 8 + length;
        let pad = (4 - (entry_len % 4)) % 4;
        if pad > 0 {
            reader.skip(pad).ok();
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal one-section `PropertySetStream`: a header naming one FMTID/offset,
    /// and a section with the given `(id, TypedPropertyValue bytes)` entries. Returns the
    /// whole stream's bytes.
    fn build_stream(fmtid: [u8; 16], props: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&BYTE_ORDER_MARKER.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // version
        out.extend_from_slice(&0u32.to_le_bytes()); // system identifier
        out.extend_from_slice(&[0u8; 16]); // clsid
        out.extend_from_slice(&1u32.to_le_bytes()); // NumPropertySets
        out.extend_from_slice(&fmtid);
        let offset0_pos = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // placeholder Offset0

        let section_start = out.len() as u32;
        out[offset0_pos..offset0_pos + 4].copy_from_slice(&section_start.to_le_bytes());

        let mut section = Vec::new();
        // Size placeholder; NumProperties + offset table follow.
        section.extend_from_slice(&0u32.to_le_bytes());
        section.extend_from_slice(&(props.len() as u32).to_le_bytes());
        let table_len = 8 * props.len();
        let mut value_bytes = Vec::new();
        let header_len = 8 + table_len; // Size + NumProperties + table
        for (id, value) in props {
            let rel_offset = (header_len + value_bytes.len()) as u32;
            section.extend_from_slice(&id.to_le_bytes());
            section.extend_from_slice(&rel_offset.to_le_bytes());
            value_bytes.extend_from_slice(value);
        }
        section.extend_from_slice(&value_bytes);
        let size = section.len() as u32;
        section[0..4].copy_from_slice(&size.to_le_bytes());

        out.extend_from_slice(&section);
        out
    }

    fn i2_bytes(value: i16) -> Vec<u8> {
        let mut b = vec![0x02, 0x00, 0x00, 0x00];
        b.extend_from_slice(&value.to_le_bytes());
        b
    }

    fn lpstr_bytes(text: &str) -> Vec<u8> {
        let mut b = vec![0x1E, 0x00, 0x00, 0x00];
        let mut payload = text.as_bytes().to_vec();
        payload.push(0);
        b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        b.extend_from_slice(&payload);
        b
    }

    #[test]
    fn parses_a_section_with_out_of_order_properties_and_an_odd_length_string() {
        // The point of this fixture: property ids stored out of numeric order, AND an
        // odd-length VT_LPSTR needing padding before the next property's offset -- a parser
        // that reads sequentially instead of following the offset table would get this wrong.
        let fmtid = [0x11u8; 16];
        let props = vec![
            (1u32, i2_bytes(1252)),       // PID_CODEPAGE
            (4u32, lpstr_bytes("Sam")),   // PIDSI_AUTHOR ("Sam\0" = 4 bytes, odd un-padded case)
            (2u32, lpstr_bytes("Title")), // PIDSI_TITLE, appears after PID 4 on the wire
        ];
        let bytes = build_stream(fmtid, &props);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.sections.len(), 1);
        let section = &parsed.sections[0];
        assert_eq!(section.fmtid, fmtid);
        assert_eq!(section.code_page, CodePage::Known(1252));
        assert_eq!(section.text(4).as_deref(), Some("Sam"));
        assert_eq!(section.text(2).as_deref(), Some("Title"));
    }

    #[test]
    fn an_unreadable_property_is_skipped_not_fatal() {
        let fmtid = [0x22u8; 16];
        // Property 5 claims an absurd VT_LPSTR length that runs past the buffer.
        let mut bad = vec![0x1E, 0x00, 0x00, 0x00];
        bad.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let props = vec![(2u32, lpstr_bytes("ok")), (5u32, bad)];
        let bytes = build_stream(fmtid, &props);
        let parsed = parse(&bytes).unwrap();
        let section = &parsed.sections[0];
        assert_eq!(section.text(2).as_deref(), Some("ok"));
        assert!(section.get(5).is_none());
    }

    #[test]
    fn a_dictionary_names_a_user_defined_property() {
        let fmtid = [0x33u8; 16];
        // Dictionary (id 0): one entry naming property id 2 as "Custom1".
        let mut dict = 1u32.to_le_bytes().to_vec(); // Count = 1
        dict.extend_from_slice(&2u32.to_le_bytes()); // PropertyIdentifier
        let name = b"Custom1";
        dict.extend_from_slice(&(name.len() as u32).to_le_bytes());
        dict.extend_from_slice(name);
        // pad entry (8 + 7 = 15 bytes) to a 4-byte boundary -> 1 pad byte
        dict.push(0);

        let props = vec![(0u32, dict), (2u32, lpstr_bytes("value"))];
        let bytes = build_stream(fmtid, &props);
        let parsed = parse(&bytes).unwrap();
        let section = &parsed.sections[0];
        let named = section.user_defined_properties();
        let custom = named
            .iter()
            .find(|p| p.id == 2)
            .expect("property 2 present");
        assert_eq!(custom.name.as_deref(), Some("Custom1"));
        assert_eq!(custom.value.as_str(), Some("value"));
    }

    #[test]
    fn rejects_a_bad_byte_order_marker() {
        let mut bytes = build_stream([0u8; 16], &[]);
        bytes[0] = 0x00;
        bytes[1] = 0x00;
        assert!(parse(&bytes).is_err());
    }
}
