//! The mini-FAT: a second, finer-grained allocation table used for streams smaller than the
//! header's `mini_stream_cutoff_size` (normally 4096 bytes). Those streams live packed together
//! inside the Root Entry's own stream (the "mini stream"), addressed in 64-byte mini sectors
//! rather than whole regular sectors.

use forensic_rs::ensure_buffer_range;
use forensic_rs::prelude::*;

use crate::chain::follow_chain;
use crate::consts::MINI_SECTOR_SIZE;
use crate::fat::read_stream_chain;
use crate::header::Header;

/// Reads the mini-FAT table itself: a regular sector chain (via `fat`), reinterpreted as
/// `u32` mini-sector-chain entries.
pub fn build_mini_fat(data: &[u8], fat: &[u32], header: &Header) -> ForensicResult<Vec<u32>> {
    let Some(start) = header.first_mini_fat_sector else {
        return Ok(Vec::new());
    };
    let bytes = read_stream_chain(data, fat, start, header.sector_size)?;
    Ok(bytes.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect())
}

/// Reads one mini sector's bytes directly out of the mini stream.
fn read_mini_sector(mini_stream: &[u8], sector_num: u32, sector_size: usize) -> ForensicResult<&[u8]> {
    let start = (sector_num as usize).saturating_mul(sector_size);
    let end = start
        .checked_add(sector_size)
        .ok_or_else(|| ForensicError::invalid_format("ole_mini_sector", "mini sector offset overflow"))?;
    ensure_buffer_range!(mini_stream, start, end);
    Ok(&mini_stream[start..end])
}

/// Reads a small stream's bytes by following its chain through the mini-FAT, inside the
/// already-materialized mini stream.
pub fn read_mini_chain(mini_stream: &[u8], mini_fat: &[u32], start_mini_sector: u32) -> ForensicResult<Vec<u8>> {
    follow_chain(mini_fat, start_mini_sector, |sector_num| {
        read_mini_sector(mini_stream, sector_num, MINI_SECTOR_SIZE)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::ENDOFCHAIN;

    #[test]
    fn reads_a_chained_mini_stream() {
        // mini sector 0 -> mini sector 1 -> ENDOFCHAIN
        let mini_fat = vec![1u32, ENDOFCHAIN];
        let mut mini_stream = vec![0u8; MINI_SECTOR_SIZE * 2];
        mini_stream[0] = b'A';
        mini_stream[MINI_SECTOR_SIZE] = b'B';

        let out = read_mini_chain(&mini_stream, &mini_fat, 0).unwrap();
        assert_eq!(out.len(), MINI_SECTOR_SIZE * 2);
        assert_eq!(out[0], b'A');
        assert_eq!(out[MINI_SECTOR_SIZE], b'B');
    }

    #[test]
    fn rejects_a_mini_sector_past_the_end_of_the_mini_stream() {
        let mini_fat = vec![ENDOFCHAIN];
        let mini_stream = vec![0u8; MINI_SECTOR_SIZE / 2];
        assert!(read_mini_chain(&mini_stream, &mini_fat, 0).is_err());
    }
}
