//! [MS-OLEPS] 2.16 `CodePageString` decoding, and the `PID_CODEPAGE` (property id 1) property
//! that governs which single-byte code page an `LPSTR` property in the same section is written
//! in.
//!
//! Only CP1252 (Windows Western European -- by far the common case for legacy Office documents
//! authored on a Western locale) and UTF-8 are decoded. Every other declared code page,
//! including every double-byte (CJK) one, is deliberately out of scope for this round -- see
//! `AnsiString::Undecodable`, which keeps the raw bytes rather than silently mangling them
//! through a wrong or absent table.

/// The code page an `LPSTR` property's bytes are declared to be written in, from this
/// property section's own `PID_CODEPAGE` property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePage {
    /// No `PID_CODEPAGE` property was present in this section.
    Absent,
    /// A code page this crate knows how to decode.
    Known(u16),
    /// A declared code page this crate has no decoder for.
    Unsupported(u16),
}

impl CodePage {
    /// `PID_CODEPAGE`'s value is stored as `VT_I2` -- a signed 16-bit integer -- but several
    /// real-world code page identifiers (e.g. 65001 for UTF-8) do not fit in `i16` and are
    /// instead written as their two's-complement negative equivalent (65001 -> -535). Bit-cast
    /// back to `u16` to recover the intended unsigned identifier before matching it.
    pub fn from_raw(raw: i16) -> Self {
        if raw == 0 {
            return CodePage::Absent;
        }
        match raw as u16 {
            1252 => CodePage::Known(1252),
            65001 => CodePage::Known(65001),
            other => CodePage::Unsupported(other),
        }
    }
}

/// Windows-1252 0x80..=0x9F -- the block where CP1252 diverges from Latin-1/ISO-8859-1 (0xA0..
/// maps straight onto the same Unicode code points as the raw byte value). `None` marks the
/// five code points CP1252 leaves undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D).
const CP1252_HIGH: [Option<char>; 32] = [
    Some('\u{20AC}'),
    None,
    Some('\u{201A}'),
    Some('\u{0192}'),
    Some('\u{201E}'),
    Some('\u{2026}'),
    Some('\u{2020}'),
    Some('\u{2021}'),
    Some('\u{02C6}'),
    Some('\u{2030}'),
    Some('\u{0160}'),
    Some('\u{2039}'),
    Some('\u{0152}'),
    None,
    Some('\u{017D}'),
    None,
    None,
    Some('\u{2018}'),
    Some('\u{2019}'),
    Some('\u{201C}'),
    Some('\u{201D}'),
    Some('\u{2022}'),
    Some('\u{2013}'),
    Some('\u{2014}'),
    Some('\u{02DC}'),
    Some('\u{2122}'),
    Some('\u{0161}'),
    Some('\u{203A}'),
    Some('\u{0153}'),
    None,
    Some('\u{017E}'),
    Some('\u{0178}'),
];

/// Decodes `raw` as Windows-1252. Returns `None` on the first byte in one of the five
/// permanently-undefined CP1252 code points, rather than silently dropping or replacing it.
pub fn decode_cp1252(raw: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    for &byte in raw {
        let ch = match byte {
            0x00..=0x7F | 0xA0..=0xFF => byte as char,
            0x80..=0x9F => CP1252_HIGH[(byte - 0x80) as usize]?,
        };
        out.push(ch);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_euro_sign_and_curly_apostrophe() {
        // 0x80 = EURO SIGN, 0x92 = RIGHT SINGLE QUOTATION MARK -- naive Latin-1 gets the
        // apostrophe wrong (it would decode 0x92 as U+0092, a C1 control code).
        assert_eq!(decode_cp1252(&[0x80]).as_deref(), Some("\u{20AC}"));
        assert_eq!(decode_cp1252(&[0x92]).as_deref(), Some("\u{2019}"));
    }

    #[test]
    fn an_undefined_code_point_makes_the_whole_string_undecodable() {
        assert!(decode_cp1252(&[b'A', 0x81, b'B']).is_none());
    }

    #[test]
    fn ascii_and_latin1_range_pass_through_unchanged() {
        assert_eq!(decode_cp1252(b"Hello").as_deref(), Some("Hello"));
        assert_eq!(decode_cp1252(&[0xE9]).as_deref(), Some("\u{00E9}")); // 'e' with acute accent
    }

    #[test]
    fn code_page_from_raw_recovers_utf8_from_its_negative_encoding() {
        assert_eq!(CodePage::from_raw(-535), CodePage::Known(65001));
        assert_eq!(CodePage::from_raw(1252), CodePage::Known(1252));
        assert_eq!(CodePage::from_raw(0), CodePage::Absent);
        assert_eq!(CodePage::from_raw(932), CodePage::Unsupported(932));
    }
}
