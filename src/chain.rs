//! A generic, cycle-safe walker over a FAT-style sector chain.
//!
//! Both the regular FAT (chaining whole sectors) and the mini-FAT (chaining 64-byte mini
//! sectors inside the mini stream) are "follow an index until you see `ENDOFCHAIN`" structures.
//! [`follow_chain`] implements that walk once, shared by [`crate::fat`] and [`crate::minifat`],
//! guarded against exactly the kind of adversarial/corrupt input a forensic tool must expect:
//! a chain that loops back on itself, or one that runs longer than the table backing it, ends
//! this walk with a [`ForensicError`] instead of hanging or panicking.

use std::collections::HashSet;

use forensic_rs::ensure_buffer_range;
use forensic_rs::prelude::*;

use crate::consts::ENDOFCHAIN;

/// Follows the chain starting at `start` through `table` (a FAT or mini-FAT), concatenating
/// whatever `read_unit` returns for each visited index.
///
/// `start >= ENDOFCHAIN` (any of the reserved markers) means "empty stream" and returns
/// `Ok(Vec::new())` immediately, matching how a zero-length stream's `start_sector` is encoded.
pub fn follow_chain<'a>(
    table: &[u32],
    start: u32,
    mut read_unit: impl FnMut(u32) -> ForensicResult<&'a [u8]>,
) -> ForensicResult<Vec<u8>> {
    if start >= ENDOFCHAIN {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    let mut current = start;
    loop {
        if !visited.insert(current) {
            return Err(ForensicError::invalid_format(
                "ole_sector_chain",
                format!("cyclic sector chain detected at sector {current}"),
            ));
        }
        out.extend_from_slice(read_unit(current)?);
        let idx = current as usize;
        ensure_buffer_range!(table, idx, idx + 1);
        let next = table[idx];
        if next >= ENDOFCHAIN {
            break;
        }
        current = next;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_a_simple_chain() {
        // sector 0 -> sector 2 -> ENDOFCHAIN
        let table = vec![2u32, ENDOFCHAIN, ENDOFCHAIN];
        let units: [&[u8]; 3] = [b"AA", b"BB", b"CC"];
        let out = follow_chain(&table, 0, |s| Ok(units[s as usize])).unwrap();
        assert_eq!(out, b"AACC");
    }

    #[test]
    fn empty_stream_start_returns_empty_output() {
        let table: Vec<u32> = vec![];
        let out = follow_chain(&table, ENDOFCHAIN, |_| Ok(&b""[..])).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn detects_a_self_referencing_cycle_instead_of_hanging() {
        let table = vec![0u32]; // sector 0 points to itself
        let result = follow_chain(&table, 0, |_| Ok(&b"x"[..]));
        assert!(result.is_err());
    }

    #[test]
    fn detects_a_longer_cycle_instead_of_hanging() {
        // 0 -> 1 -> 0 -> ...
        let table = vec![1u32, 0u32];
        let result = follow_chain(&table, 0, |_| Ok(&b"x"[..]));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_a_sector_number_past_the_end_of_the_table() {
        let table = vec![5u32];
        let result = follow_chain(&table, 0, |_| Ok(&b"x"[..]));
        assert!(result.is_err());
    }
}
