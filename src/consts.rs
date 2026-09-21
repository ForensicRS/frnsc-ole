//! Constants from the [MS-CFB] Compound File Binary File Format specification.

/// The fixed 8-byte magic every CFBF file starts with.
pub const OLE_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Size of the fixed header at the start of every CFBF file.
pub const HEADER_SIZE: usize = 512;

/// Size in bytes of one Directory Entry record.
pub const DIRECTORY_ENTRY_SIZE: usize = 128;

/// Number of DIFAT entries stored directly in the header.
pub const HEADER_DIFAT_ENTRIES: usize = 109;

/// Fixed mini sector size (mini_sector_shift is always 6 -> 2^6 = 64).
pub const MINI_SECTOR_SIZE: usize = 64;

// Special FAT/DIFAT/mini-FAT sector-number markers (spec section 2.1).
/// Marks the last sector of a chain.
pub const ENDOFCHAIN: u32 = 0xFFFFFFFE;
/// Marks a sector that is not part of any chain (free space).
#[allow(dead_code)] // spec-documentation constant; only exercised in tests today
pub const FREESECT: u32 = 0xFFFFFFFF;
/// Marks a sector that holds part of the FAT itself.
#[allow(dead_code)] // spec-documentation constant; only exercised in tests today
pub const FATSECT: u32 = 0xFFFFFFFD;
/// Marks a sector that holds part of the DIFAT itself.
pub const DIFSECT: u32 = 0xFFFFFFFC;

/// The highest sector number that can legitimately address user data — every special marker
/// above this value (`DIFSECT`..=`FREESECT`) is reserved, never a real sector.
pub const MAX_REGULAR_SECTOR: u32 = 0xFFFFFFF9;

/// `child_id`/`left_sibling_id`/`right_sibling_id` value meaning "no such entry".
pub const NOSTREAM: u32 = 0xFFFFFFFF;
