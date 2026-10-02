//! [MS-OLEPS] 2.15 `TypedPropertyValue` decoding: the `VT_*` variant type tag plus its value,
//! for the subset of types this crate's known SummaryInformation/DocumentSummaryInformation
//! fields actually use.

use forensic_rs::prelude::*;

use super::codepage::{CodePage, decode_cp1252};

// VARENUM values ([MS-OAUT] 2.2.7 / [MS-OLEPS] 2.15) this decoder recognizes.
const VT_EMPTY: u16 = 0x0000;
const VT_NULL: u16 = 0x0001;
const VT_I2: u16 = 0x0002;
const VT_I4: u16 = 0x0003;
const VT_R4: u16 = 0x0004;
const VT_R8: u16 = 0x0005;
const VT_BOOL: u16 = 0x000B;
const VT_LPSTR: u16 = 0x001E;
const VT_LPWSTR: u16 = 0x001F;
const VT_FILETIME: u16 = 0x0040;
const VT_VECTOR: u16 = 0x1000;

/// An `LPSTR` property's bytes, decoded per this section's declared [`CodePage`] (or left
/// undecoded when no supported decoder applies). Every text accessor built on this yields
/// `None` for [`AnsiString::Undecodable`] -- an empty string never silently substitutes for
/// "could not decode".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnsiString {
    /// Decoded via a known, non-ASCII-only code page.
    Decoded { text: String, code_page: u16 },
    /// No code page was declared, and every byte was plain ASCII -- decodable without needing
    /// to know the code page at all.
    Ascii(String),
    /// Could not be decoded: no code page was declared and the bytes are not pure ASCII, the
    /// declared code page has no decoder in this crate, or the bytes are invalid for the
    /// decoder that was used (e.g. not valid UTF-8 under a declared UTF-8 code page).
    Undecodable { raw: Vec<u8> },
}

impl AnsiString {
    pub fn decode(raw: &[u8], code_page: CodePage) -> Self {
        match code_page {
            CodePage::Known(1252) => match decode_cp1252(raw) {
                Some(text) => AnsiString::Decoded {
                    text,
                    code_page: 1252,
                },
                None => AnsiString::Undecodable { raw: raw.to_vec() },
            },
            CodePage::Known(65001) => match std::str::from_utf8(raw) {
                Ok(text) => AnsiString::Decoded {
                    text: text.to_string(),
                    code_page: 65001,
                },
                Err(_) => AnsiString::Undecodable { raw: raw.to_vec() },
            },
            CodePage::Known(_) | CodePage::Unsupported(_) => {
                AnsiString::Undecodable { raw: raw.to_vec() }
            }
            CodePage::Absent => {
                if raw.iter().all(|&b| b < 0x80) {
                    // `raw` is ASCII-only by the check above, so this can never fail.
                    AnsiString::Ascii(String::from_utf8(raw.to_vec()).unwrap_or_default())
                } else {
                    AnsiString::Undecodable { raw: raw.to_vec() }
                }
            }
        }
    }

    /// `Some` for every successfully decoded state, `None` for [`AnsiString::Undecodable`] --
    /// never an empty string standing in for "could not decode".
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AnsiString::Decoded { text, .. } => Some(text),
            AnsiString::Ascii(text) => Some(text),
            AnsiString::Undecodable { .. } => None,
        }
    }
}

/// One decoded [MS-OLEPS] 2.15 typed property value.
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyValue {
    Empty,
    Null,
    I2(i16),
    I4(i32),
    R4(f32),
    R8(f64),
    /// `VT_BOOL` is a 16-bit field where only `0x0000` (false) and `0xFFFF` (true) are valid
    /// per spec; anything else is a malformed property, not silently coerced to `true`.
    Bool(bool),
    AnsiStr(AnsiString),
    UnicodeStr(String),
    /// A `VT_FILETIME` value, kept in both forms because [MS-OLEPS] reuses this same on-disk
    /// type for two different meanings: an absolute instant (`PIDSI_CREATE_DTM`,
    /// `PIDSI_LASTSAVE_DTM`, `PIDSI_LASTPRINTED`) *and* a plain duration
    /// (`PIDSI_EDITTIME` -- total editing time, counted from an arbitrary zero, not from
    /// 1601-01-01). `timestamp` is `None` for an all-zero FILETIME (unset, same convention as
    /// [`crate::directory::DirectoryEntry`]'s timestamps) or when a duration field's `raw`
    /// ticks would decode to a nonsensical instant; callers that know they have a duration
    /// field should read `raw` directly instead.
    FileTime {
        raw: u64,
        timestamp: Option<ForensicTimestamp>,
    },
    Vector(Vec<PropertyValue>),
    /// A `VT_*` this crate does not decode. `raw` is a bounded diagnostic preview (see
    /// [`UNSUPPORTED_RAW_PREVIEW`]) of the bytes starting at this value, not a complete capture
    /// -- there is no way to know the value's true length without knowing its type, and
    /// capturing "everything left in the section" would multiply badly inside a `VT_VECTOR` of
    /// unsupported elements.
    Unsupported {
        vt: u16,
        raw: Vec<u8>,
    },
}

impl PropertyValue {
    /// The property's text, if it decoded to one and (for `AnsiStr`) it decoded successfully.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PropertyValue::AnsiStr(s) => s.as_str(),
            PropertyValue::UnicodeStr(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i32(&self) -> Option<i32> {
        match self {
            PropertyValue::I2(v) => Some(*v as i32),
            PropertyValue::I4(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_i32().and_then(|v| u64::try_from(v).ok())
    }

    pub fn as_filetime(&self) -> Option<ForensicTimestamp> {
        match self {
            PropertyValue::FileTime { timestamp, .. } => *timestamp,
            _ => None,
        }
    }

    /// The raw 100-nanosecond tick count backing a `VT_FILETIME` value, before any
    /// epoch-relative interpretation -- what a duration field (`PIDSI_EDITTIME`) actually means.
    pub fn as_filetime_raw(&self) -> Option<u64> {
        match self {
            PropertyValue::FileTime { raw, .. } => Some(*raw),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PropertyValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Reads one full `TypedPropertyValue` (the `Type`/`Padding` header plus its value) at the
/// reader's current position.
pub fn read_typed_value(
    reader: &mut ByteReader,
    code_page: CodePage,
) -> ForensicResult<PropertyValue> {
    let vt = reader.read_u16_le()?;
    let _padding = reader.read_u16_le()?;
    if vt & VT_VECTOR != 0 {
        let base_vt = vt & !VT_VECTOR;
        let count = reader.read_u32_le()?;
        // A corrupt/adversarial count could otherwise drive an unbounded allocation before the
        // first out-of-range read is even attempted.
        let count = count.min(reader.remaining() as u32 / 4 + 1);
        let mut values = Vec::with_capacity(count as usize);
        // If `base_vt` is itself unsupported, its true byte length is unknowable, so the
        // reader's position after it is unreliable -- every subsequent element in this vector
        // then decodes from the wrong offset too. This is an inherent limit of an unrecognized
        // vector element type, not something a bounds fix can repair; `Unsupported`'s bounded
        // `raw` preview exists so this degrades to "diagnostic garbage", never an unbounded
        // memory grab (see `read_value_of_type`'s fallback arm).
        for _ in 0..count {
            values.push(read_value_of_type(reader, base_vt, code_page)?);
        }
        return Ok(PropertyValue::Vector(values));
    }
    read_value_of_type(reader, vt, code_page)
}

/// Reads one value of a known base `VT_*` type (no `Type`/`Padding` header -- used both for a
/// scalar property's value and for each element of a `VT_VECTOR`).
fn read_value_of_type(
    reader: &mut ByteReader,
    vt: u16,
    code_page: CodePage,
) -> ForensicResult<PropertyValue> {
    match vt {
        VT_EMPTY => Ok(PropertyValue::Empty),
        VT_NULL => Ok(PropertyValue::Null),
        VT_I2 => Ok(PropertyValue::I2(reader.read_i16_le()?)),
        VT_I4 => Ok(PropertyValue::I4(reader.read_i32_le()?)),
        VT_R4 => Ok(PropertyValue::R4(reader.read_f32_le()?)),
        VT_R8 => Ok(PropertyValue::R8(reader.read_f64_le()?)),
        VT_BOOL => {
            let raw = reader.read_u16_le()?;
            match raw {
                0x0000 => Ok(PropertyValue::Bool(false)),
                0xFFFF => Ok(PropertyValue::Bool(true)),
                other => Ok(PropertyValue::Unsupported {
                    vt,
                    raw: other.to_le_bytes().to_vec(),
                }),
            }
        }
        VT_LPSTR => {
            let len = reader.read_u32_le()? as usize;
            let bytes = reader.read_bytes(len)?;
            let trimmed = trim_trailing_nul(bytes);
            Ok(PropertyValue::AnsiStr(AnsiString::decode(
                trimmed, code_page,
            )))
        }
        VT_LPWSTR => {
            let len_chars = reader.read_u32_le()? as usize;
            let bytes = reader.read_bytes(len_chars.saturating_mul(2))?;
            let mut sub = ByteReader::new(bytes);
            let text = sub.read_utf16le_string(bytes.len())?;
            Ok(PropertyValue::UnicodeStr(
                text.trim_end_matches('\0').to_string(),
            ))
        }
        VT_FILETIME => {
            let raw = reader.read_u64_le()?;
            let timestamp = if raw == 0 {
                None
            } else {
                Some(ForensicTimestamp::from_win_filetime(raw))
            };
            Ok(PropertyValue::FileTime { raw, timestamp })
        }
        _ => {
            // There is no way to know an unknown type's true length, so this cannot consume
            // exactly the right number of bytes -- but it must not capture the *rest of the
            // whole section buffer* either. That matters most inside a `VT_VECTOR`: each
            // element would otherwise re-capture the same enormous remaining slice, multiplying
            // a single unsupported vector property into megabytes of duplicated raw bytes. A
            // small bounded diagnostic prefix is enough to identify the value without that.
            let raw = reader
                .peek_bytes(reader.remaining().min(UNSUPPORTED_RAW_PREVIEW))
                .unwrap_or(&[])
                .to_vec();
            Ok(PropertyValue::Unsupported { vt, raw })
        }
    }
}

/// Cap on how many bytes [`read_value_of_type`]'s fallback arm captures for a `VT_*` this crate
/// does not decode -- a diagnostic preview, not a full capture (see the comment at its call
/// site for why an unbounded capture is actively harmful inside a `VT_VECTOR`).
const UNSUPPORTED_RAW_PREVIEW: usize = 64;

fn trim_trailing_nul(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(pos) => &bytes[..pos],
        None => bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(bytes: &[u8], code_page: CodePage) -> PropertyValue {
        let mut reader = ByteReader::new(bytes);
        read_typed_value(&mut reader, code_page).unwrap()
    }

    #[test]
    fn decodes_vt_i2_and_vt_i4() {
        assert_eq!(
            read(&[0x02, 0x00, 0x00, 0x00, 0x2A, 0x00], CodePage::Absent),
            PropertyValue::I2(42)
        );
        assert_eq!(
            read(
                &[0x03, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00],
                CodePage::Absent
            ),
            PropertyValue::I4(42)
        );
    }

    #[test]
    fn decodes_a_zero_filetime_as_none() {
        let mut bytes = vec![0x40, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            read(&bytes, CodePage::Absent),
            PropertyValue::FileTime {
                raw: 0,
                timestamp: None
            }
        );
    }

    #[test]
    fn a_bool_that_is_neither_0_nor_0xffff_is_unsupported_not_coerced_to_true() {
        let bytes = [0x0B, 0x00, 0x00, 0x00, 0x01, 0x00]; // 0x0001 -- not a valid VT_BOOL value
        match read(&bytes, CodePage::Absent) {
            PropertyValue::Unsupported { vt, .. } => assert_eq!(vt, VT_BOOL),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn decodes_a_vector_of_lpwstr() {
        let mut bytes = vec![0x1F, 0x10, 0x00, 0x00]; // VT_VECTOR | VT_LPWSTR
        bytes.extend_from_slice(&2u32.to_le_bytes()); // count = 2
        // element 0: "ab" + NUL (3 chars)
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(
            "ab\0"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<u8>>()
                .as_slice(),
        );
        // element 1: "c" + NUL (2 chars)
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(
            "c\0"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<u8>>()
                .as_slice(),
        );

        match read(&bytes, CodePage::Absent) {
            PropertyValue::Vector(values) => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0].as_str(), Some("ab"));
                assert_eq!(values[1].as_str(), Some("c"));
            }
            other => panic!("expected Vector, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_vt_does_not_error_it_captures_raw_bytes() {
        let bytes = [0x47, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]; // VT_CF, unsupported
        match read(&bytes, CodePage::Absent) {
            PropertyValue::Unsupported { vt, raw } => {
                assert_eq!(vt, 0x47);
                assert_eq!(raw, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn decodes_an_lpstr_under_cp1252() {
        let mut bytes = vec![0x1E, 0x00, 0x00, 0x00]; // VT_LPSTR
        let payload = [0x80, 0x00]; // EURO SIGN + NUL, length 2
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&payload);
        match read(&bytes, CodePage::Known(1252)) {
            PropertyValue::AnsiStr(s) => assert_eq!(s.as_str(), Some("\u{20AC}")),
            other => panic!("expected AnsiStr, got {other:?}"),
        }
    }

    #[test]
    fn an_unsupported_vector_element_does_not_capture_the_whole_remaining_buffer() {
        // VT_VECTOR | VT_VARIANT (0x0C), an unsupported base type, with a large trailing
        // buffer that must NOT end up duplicated into every element's `raw` capture.
        let mut bytes = vec![0x0C, 0x10, 0x00, 0x00];
        bytes.extend_from_slice(&2u32.to_le_bytes()); // count = 2
        let tail = vec![0xAAu8; 10_000];
        bytes.extend_from_slice(&tail);
        match read(&bytes, CodePage::Absent) {
            PropertyValue::Vector(values) => {
                assert_eq!(values.len(), 2);
                for v in values {
                    match v {
                        PropertyValue::Unsupported { raw, .. } => {
                            assert!(raw.len() <= UNSUPPORTED_RAW_PREVIEW)
                        }
                        other => panic!("expected Unsupported, got {other:?}"),
                    }
                }
            }
            other => panic!("expected Vector, got {other:?}"),
        }
    }
}
