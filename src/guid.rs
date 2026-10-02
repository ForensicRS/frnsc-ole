//! Formats a 16-byte CFBF/COM CLSID as the canonical GUID string
//! (`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`).
//!
//! A CLSID on the wire is stored in *mixed-endian* order ([MS-DTYP] 2.3.4): the first `u32` and
//! the two following `u16`s are little-endian, but the trailing 8 bytes are taken verbatim
//! (effectively big-endian, since they are usually written as a big-endian byte sequence in
//! reference material). The crate's original code rendered the raw byte array with Rust's
//! `{:02x?}` debug formatter — `[06, 09, 02, 00, ...]` — which is not a GUID at all; this module
//! exists to fix that in one place.

/// Renders `clsid` (as stored in a [`crate::directory::DirectoryEntry`]) as
/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
pub fn format_clsid(clsid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([clsid[0], clsid[1], clsid[2], clsid[3]]);
    let d2 = u16::from_le_bytes([clsid[4], clsid[5]]);
    let d3 = u16::from_le_bytes([clsid[6], clsid[7]]);
    let d4 = &clsid[8..16];
    format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_word_document_8_clsid() {
        // {00020906-0000-0000-C000-000000000046} -- Word.Document.8's CLSID, on the wire as
        // little-endian d1/d2/d3 followed by the eight big-endian-order trailing bytes.
        let bytes: [u8; 16] = [
            0x06, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ];
        assert_eq!(
            format_clsid(&bytes),
            "{00020906-0000-0000-C000-000000000046}"
        );
    }

    #[test]
    fn the_old_debug_array_format_is_not_what_this_produces() {
        let bytes: [u8; 16] = [
            0x06, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ];
        let old_style = format!("{bytes:02x?}");
        assert_ne!(format_clsid(&bytes), old_style);
    }

    #[test]
    fn formats_an_all_zero_clsid_as_the_nil_guid() {
        assert_eq!(
            format_clsid(&[0u8; 16]),
            "{00000000-0000-0000-0000-000000000000}"
        );
    }
}
