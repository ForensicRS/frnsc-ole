//! Builds the FAT (sector allocation table) from a header's DIFAT, and reads whole sector
//! chains out of the file's bytes.

use std::collections::HashSet;

use forensic_rs::{ensure_buffer_range, ensure_format};
use forensic_rs::prelude::*;

use crate::chain::follow_chain;
use crate::consts::MAX_REGULAR_SECTOR;
use crate::header::Header;

/// Reads one regular sector's bytes directly out of the file buffer.
///
/// The header block always occupies exactly one whole sector, however large that sector is —
/// for a 512-byte-sector (major version 3) file that's the same 512 bytes the header itself
/// uses, but for a 4096-byte-sector (major version 4) file the header's 512 bytes are padded
/// out to a full 4096-byte block before sector 0 begins. So sector 0 starts at byte offset
/// `sector_size`, not at the fixed 512-byte header size — a file with 4096-byte sectors (the
/// common case for real-world `.msi` files) would otherwise have every sector read 3584 bytes
/// short of where it actually is.
///
/// Also bounds-checked (`ensure_buffer_range!`) rather than trusting the sector number — the
/// original version of this parser indexed straight into a `Vec<u8>` with no such check, which
/// panics on a sector number a corrupt or adversarial file can set arbitrarily.
pub fn read_sector(data: &[u8], sector_num: u32, sector_size: usize) -> ForensicResult<&[u8]> {
    let start = sector_size
        .checked_add((sector_num as usize).saturating_mul(sector_size))
        .ok_or_else(|| ForensicError::invalid_format("ole_sector", "sector offset overflow"))?;
    let end = start
        .checked_add(sector_size)
        .ok_or_else(|| ForensicError::invalid_format("ole_sector", "sector offset overflow"))?;
    ensure_buffer_range!(data, start, end);
    Ok(&data[start..end])
}

/// Builds the full FAT sector-number table: the 109 entries in the header, plus any additional
/// DIFAT sectors chained off `header.first_difat_sector`.
///
/// The DIFAT chain walk is cycle-guarded independently of [`follow_chain`] (it addresses
/// sectors directly, not through a FAT it is itself building) and capped by the header's own
/// declared `num_difat_sectors`, so a self-referential or over-long DIFAT chain fails with a
/// [`ForensicError`] instead of looping forever.
pub fn build_fat(data: &[u8], header: &Header) -> ForensicResult<Vec<u32>> {
    let mut fat_sectors = Vec::new();
    for &entry in header.difat.iter() {
        if entry <= MAX_REGULAR_SECTOR {
            fat_sectors.push(entry);
        }
    }

    if let Some(first) = header.first_difat_sector {
        let entries_per_sector = header.sector_size / 4;
        ensure_format!(entries_per_sector > 1, "ole_difat", "sector too small to hold a DIFAT chain link");
        let mut visited = HashSet::new();
        let mut current = first;
        loop {
            if !visited.insert(current) {
                return Err(ForensicError::invalid_format(
                    "ole_difat",
                    format!("cyclic DIFAT chain at sector {current}"),
                ));
            }
            if visited.len() as u32 > header.num_difat_sectors + 1 {
                return Err(ForensicError::invalid_format(
                    "ole_difat",
                    "DIFAT chain is longer than the header declares",
                ));
            }
            let sector = read_sector(data, current, header.sector_size)?;
            for chunk in sector[..(entries_per_sector - 1) * 4].chunks_exact(4) {
                let value = u32::from_le_bytes(chunk.try_into().unwrap());
                if value <= MAX_REGULAR_SECTOR {
                    fat_sectors.push(value);
                }
            }
            let next_bytes = &sector[(entries_per_sector - 1) * 4..entries_per_sector * 4];
            let next = u32::from_le_bytes(next_bytes.try_into().unwrap());
            if next >= crate::consts::ENDOFCHAIN {
                break;
            }
            current = next;
        }
    }

    let mut fat = Vec::with_capacity(fat_sectors.len() * (header.sector_size / 4));
    for &sector_num in &fat_sectors {
        let sector = read_sector(data, sector_num, header.sector_size)?;
        for chunk in sector.chunks_exact(4) {
            fat.push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }
    }
    Ok(fat)
}

/// Reads a whole stream's bytes by following its sector chain through `fat`, starting at
/// `start_sector`.
pub fn read_stream_chain(data: &[u8], fat: &[u32], start_sector: u32, sector_size: usize) -> ForensicResult<Vec<u8>> {
    follow_chain(fat, start_sector, |sector_num| read_sector(data, sector_num, sector_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{ENDOFCHAIN, FREESECT, HEADER_SIZE};

    fn header_with_difat(sector_size: usize, difat: [u32; crate::consts::HEADER_DIFAT_ENTRIES]) -> Header {
        Header {
            major_version: 3,
            minor_version: 0,
            sector_size,
            mini_stream_cutoff_size: 4096,
            first_directory_sector: None,
            first_mini_fat_sector: None,
            first_difat_sector: None,
            num_difat_sectors: 0,
            difat,
        }
    }

    #[test]
    fn builds_fat_from_header_difat_entries_only() {
        let mut difat = [FREESECT; crate::consts::HEADER_DIFAT_ENTRIES];
        difat[0] = 0; // sector 0 holds the FAT
        let header = header_with_difat(512, difat);

        let mut data = vec![0u8; HEADER_SIZE + 512];
        // FAT sector 0: entry[0] = ENDOFCHAIN (only fat entry that matters for this test)
        data[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&ENDOFCHAIN.to_le_bytes());

        let fat = build_fat(&data, &header).unwrap();
        assert_eq!(fat.len(), 512 / 4);
        assert_eq!(fat[0], ENDOFCHAIN);
    }

    #[test]
    fn read_sector_rejects_an_out_of_range_sector_instead_of_panicking() {
        let data = vec![0u8; HEADER_SIZE + 512];
        assert!(read_sector(&data, 100, 512).is_err());
    }
}
