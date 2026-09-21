//! Parses the fixed 512-byte CFBF header into a validated [`Header`].
//!
//! [`OleHeaderRaw`] decodes every field via [`ByteReader`]/[`FromBytes`] — no `unsafe` cast is
//! needed even for the 109-entry DIFAT array, since each entry is just a `u32` read off the
//! cursor. [`Header`] then validates the raw fields: a `sector_shift` other than 512/4096 is
//! rejected outright (`ForensicError`) rather than silently treated as 4096, which is what the
//! very first version of this parser used to do.

use forensic_rs::{ensure_format, ensure_min_length};
use forensic_rs::prelude::*;

use crate::consts::{HEADER_DIFAT_ENTRIES, HEADER_SIZE, OLE_SIGNATURE};

const SECTOR_SHIFT_512: u16 = 0x0009;
const SECTOR_SHIFT_4096: u16 = 0x000C;
const MINI_SECTOR_SHIFT_64: u16 = 0x0006;
const LITTLE_ENDIAN_MARKER: u16 = 0xFFFE;

pub(crate) struct OleHeaderRaw {
    pub byte_order: u16,
    pub major_version: u16,
    pub minor_version: u16,
    pub mini_sector_shift: u16,
    pub sector_shift: u16,
    pub mini_stream_cutoff_size: u32,
    pub first_directory_sector: u32,
    pub first_mini_fat_sector: u32,
    pub first_difat_sector: u32,
    pub num_difat_sectors: u32,
    pub difat: [u32; HEADER_DIFAT_ENTRIES],
}

impl FromBytes for OleHeaderRaw {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let signature = reader.read_fixed::<8>()?;
        ensure_format!(signature == OLE_SIGNATURE, "ole_header", "invalid OLE/CFBF signature");
        let _clsid = reader.read_fixed::<16>()?;
        let minor_version = reader.read_u16_le()?;
        let major_version = reader.read_u16_le()?;
        let byte_order = reader.read_u16_le()?;
        let sector_shift = reader.read_u16_le()?;
        let mini_sector_shift = reader.read_u16_le()?;
        reader.skip(6)?; // reserved
        let _num_directory_sectors = reader.read_u32_le()?;
        let _num_fat_sectors = reader.read_u32_le()?;
        let first_directory_sector = reader.read_u32_le()?;
        let _transaction_signature_number = reader.read_u32_le()?;
        let mini_stream_cutoff_size = reader.read_u32_le()?;
        let first_mini_fat_sector = reader.read_u32_le()?;
        let _num_mini_fat_sectors = reader.read_u32_le()?;
        let first_difat_sector = reader.read_u32_le()?;
        let num_difat_sectors = reader.read_u32_le()?;
        let mut difat = [0u32; HEADER_DIFAT_ENTRIES];
        for slot in difat.iter_mut() {
            *slot = reader.read_u32_le()?;
        }
        Ok(Self {
            byte_order,
            major_version,
            minor_version,
            mini_sector_shift,
            sector_shift,
            mini_stream_cutoff_size,
            first_directory_sector,
            first_mini_fat_sector,
            first_difat_sector,
            num_difat_sectors,
            difat,
        })
    }
}

/// A validated, ready-to-use view of the CFBF header.
#[derive(Debug, Clone)]
pub struct Header {
    pub major_version: u16,
    pub minor_version: u16,
    pub sector_size: usize,
    pub mini_stream_cutoff_size: usize,
    pub first_directory_sector: Option<u32>,
    pub first_mini_fat_sector: Option<u32>,
    pub first_difat_sector: Option<u32>,
    pub num_difat_sectors: u32,
    pub(crate) difat: [u32; HEADER_DIFAT_ENTRIES],
}

/// A header "first sector" pointer field uses any of the four reserved markers
/// (`DIFSECT..=FREESECT`, i.e. `>= 0xFFFFFFFC`) to mean "there is no such stream/chain" —
/// `ENDOFCHAIN` is the one actually specified for this purpose, but treating every reserved
/// marker the same way is simpler and never wrong (none of them is ever a real sector number).
fn parse_optional_sector(raw: u32) -> Option<u32> {
    if raw >= crate::consts::DIFSECT {
        None
    } else {
        Some(raw)
    }
}

impl TryFrom<OleHeaderRaw> for Header {
    type Error = ForensicError;

    fn try_from(raw: OleHeaderRaw) -> ForensicResult<Self> {
        ensure_format!(
            raw.byte_order == LITTLE_ENDIAN_MARKER,
            "ole_header",
            "unexpected byte order marker (only little-endian CFBF files are supported)"
        );
        let sector_size = match raw.sector_shift {
            SECTOR_SHIFT_512 => 512usize,
            SECTOR_SHIFT_4096 => 4096usize,
            other => {
                return Err(ForensicError::invalid_format(
                    "ole_header",
                    format!("unsupported sector shift 0x{other:04X}"),
                ));
            }
        };
        ensure_format!(
            raw.mini_sector_shift == MINI_SECTOR_SHIFT_64,
            "ole_header",
            "unsupported mini sector shift (expected 64-byte mini sectors)"
        );
        if raw.major_version == 3 {
            ensure_format!(
                sector_size == 512,
                "ole_header",
                "major version 3 requires a 512-byte sector size"
            );
        }
        Ok(Self {
            major_version: raw.major_version,
            minor_version: raw.minor_version,
            sector_size,
            mini_stream_cutoff_size: raw.mini_stream_cutoff_size as usize,
            first_directory_sector: parse_optional_sector(raw.first_directory_sector),
            first_mini_fat_sector: parse_optional_sector(raw.first_mini_fat_sector),
            first_difat_sector: parse_optional_sector(raw.first_difat_sector),
            num_difat_sectors: raw.num_difat_sectors,
            difat: raw.difat,
        })
    }
}

impl Header {
    /// Parses the first `HEADER_SIZE` bytes of `data` into a validated [`Header`].
    pub fn parse(data: &[u8]) -> ForensicResult<Self> {
        ensure_min_length!(HEADER_SIZE, data.len(), "ole_header");
        let mut reader = ByteReader::new(&data[..HEADER_SIZE]);
        let raw: OleHeaderRaw = reader.read_as()?;
        raw.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header_bytes() -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(&OLE_SIGNATURE);
        buf[26..28].copy_from_slice(&3u16.to_le_bytes()); // major_version
        buf[28..30].copy_from_slice(&LITTLE_ENDIAN_MARKER.to_le_bytes()); // byte_order
        buf[30..32].copy_from_slice(&SECTOR_SHIFT_512.to_le_bytes()); // sector_shift
        buf[32..34].copy_from_slice(&MINI_SECTOR_SHIFT_64.to_le_bytes()); // mini_sector_shift
        buf[48..52].copy_from_slice(&crate::consts::ENDOFCHAIN.to_le_bytes()); // first_directory_sector
        buf[56..60].copy_from_slice(&4096u32.to_le_bytes()); // mini_stream_cutoff_size
        buf[60..64].copy_from_slice(&crate::consts::ENDOFCHAIN.to_le_bytes()); // first_mini_fat_sector
        buf[68..72].copy_from_slice(&crate::consts::ENDOFCHAIN.to_le_bytes()); // first_difat_sector
        for slot in buf[76..76 + HEADER_DIFAT_ENTRIES * 4].chunks_exact_mut(4) {
            slot.copy_from_slice(&crate::consts::FREESECT.to_le_bytes());
        }
        buf
    }

    #[test]
    fn parses_a_well_formed_header() {
        let header = Header::parse(&valid_header_bytes()).unwrap();
        assert_eq!(header.sector_size, 512);
        assert_eq!(header.first_directory_sector, None);
    }

    #[test]
    fn rejects_a_truncated_header_without_panicking() {
        let bytes = &valid_header_bytes()[..HEADER_SIZE - 1];
        assert!(Header::parse(bytes).is_err());
    }

    #[test]
    fn rejects_a_bad_signature() {
        let mut bytes = valid_header_bytes();
        bytes[0] = 0x00;
        assert!(Header::parse(&bytes).is_err());
    }

    #[test]
    fn rejects_an_unsupported_sector_shift_instead_of_defaulting_to_4096() {
        let mut bytes = valid_header_bytes();
        bytes[30..32].copy_from_slice(&0x0001u16.to_le_bytes());
        assert!(Header::parse(&bytes).is_err());
    }
}
