//! Parses the directory stream (one 128-byte [`DirectoryEntry`] record per storage/stream) into
//! a flat, index-addressable list. Tree structure (which entry is whose child/sibling) is
//! resolved separately in [`crate::tree`].

use forensic_rs::ensure_format;
use forensic_rs::prelude::*;

use crate::consts::DIRECTORY_ENTRY_SIZE;

/// What kind of directory record an entry is — see [MS-CFB] 2.6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    /// An unused/free directory slot (padding out to a full sector).
    Unallocated,
    Storage,
    Stream,
    RootStorage,
    /// A value the spec does not assign a meaning to (or a deprecated one, e.g. `LockBytes`).
    Other(u8),
}

impl From<u8> for ObjectType {
    fn from(value: u8) -> Self {
        match value {
            0 => ObjectType::Unallocated,
            1 => ObjectType::Storage,
            2 => ObjectType::Stream,
            5 => ObjectType::RootStorage,
            other => ObjectType::Other(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub name: String,
    pub object_type: ObjectType,
    pub left_sibling_id: u32,
    pub right_sibling_id: u32,
    pub child_id: u32,
    pub clsid: [u8; 16],
    pub start_sector: u32,
    pub stream_size: u64,
    /// [MS-CFB] 2.6.1 creation time. `None` when the on-disk FILETIME is 0, which the spec
    /// mandates for stream objects (and which most writers also use for storages that were
    /// never explicitly timestamped). A zero FILETIME means unset, never 1601-01-01 -- never
    /// map it to an epoch value.
    pub created: Option<ForensicTimestamp>,
    /// [MS-CFB] 2.6.1 modification time. Same zero-means-unset rule as `created`.
    pub modified: Option<ForensicTimestamp>,
}

impl DirectoryEntry {
    /// This entry's times as [`MacbTimes`], for handing to a [`VirtualFile`]'s metadata. CFBF
    /// has neither an access time nor a metadata-change time distinct from modification, so
    /// those fields stay `None` rather than being filled in with a guess.
    pub fn macb(&self) -> MacbTimes {
        MacbTimes {
            created: self.created,
            modified: self.modified,
            accessed: None,
            changed: None,
            filename_times: None,
        }
    }

    /// Renders this entry's CLSID as a canonical mixed-endian GUID string
    /// (`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`), or `None` for an all-zero CLSID -- a null
    /// CLSID means "no class assigned", not "the class whose GUID happens to be all zeros".
    pub fn clsid_string(&self) -> Option<String> {
        if self.clsid == [0u8; 16] {
            return None;
        }
        Some(crate::guid::format_clsid(&self.clsid))
    }

    pub fn is_stream(&self) -> bool {
        matches!(self.object_type, ObjectType::Stream)
    }

    pub fn is_storage(&self) -> bool {
        matches!(
            self.object_type,
            ObjectType::Storage | ObjectType::RootStorage
        )
    }
}

struct DirectoryEntryRaw {
    name_raw: [u8; 64],
    name_length: u16,
    object_type: u8,
    left_sibling_id: u32,
    right_sibling_id: u32,
    child_id: u32,
    clsid: [u8; 16],
    creation_time: u64,
    modified_time: u64,
    start_sector: u32,
    stream_size: u64,
}

impl FromBytes for DirectoryEntryRaw {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let name_raw = reader.read_fixed::<64>()?;
        let name_length = reader.read_u16_le()?;
        let object_type = reader.read_u8()?;
        let _color_flag = reader.read_u8()?;
        let left_sibling_id = reader.read_u32_le()?;
        let right_sibling_id = reader.read_u32_le()?;
        let child_id = reader.read_u32_le()?;
        let clsid = reader.read_fixed::<16>()?;
        let _state_bits = reader.read_u32_le()?;
        let creation_time = reader.read_u64_le()?;
        let modified_time = reader.read_u64_le()?;
        let start_sector = reader.read_u32_le()?;
        let stream_size = reader.read_u64_le()?;
        Ok(Self {
            name_raw,
            name_length,
            object_type,
            left_sibling_id,
            right_sibling_id,
            child_id,
            clsid,
            creation_time,
            modified_time,
            start_sector,
            stream_size,
        })
    }
}

/// A zero FILETIME is the spec-mandated "unset" value ([MS-CFB] 2.6.1) -- never map it to the
/// 1601-01-01 instant it would otherwise decode to.
fn filetime_or_none(raw: u64) -> Option<ForensicTimestamp> {
    if raw == 0 {
        None
    } else {
        Some(ForensicTimestamp::from_win_filetime(raw))
    }
}

impl DirectoryEntryRaw {
    /// Validates and decodes the raw record. The original version of this parser computed
    /// `name_length - 2` unconditionally, which underflows (and panics in debug builds, wraps
    /// to a huge length in release) whenever `name_length == 0` — an unused directory slot's
    /// completely ordinary state. Bounds-checking first turns that into a clean `Err`.
    fn into_entry(self) -> ForensicResult<DirectoryEntry> {
        ensure_format!(
            self.name_length % 2 == 0 && self.name_length as usize <= self.name_raw.len(),
            "ole_directory_entry",
            "directory entry name length is odd or exceeds the 64-byte name field"
        );
        let name = if self.name_length >= 2 {
            let mut reader = ByteReader::new(&self.name_raw);
            reader.read_utf16le_string((self.name_length - 2) as usize)?
        } else {
            String::new()
        };
        Ok(DirectoryEntry {
            name,
            object_type: ObjectType::from(self.object_type),
            left_sibling_id: self.left_sibling_id,
            right_sibling_id: self.right_sibling_id,
            child_id: self.child_id,
            clsid: self.clsid,
            start_sector: self.start_sector,
            stream_size: self.stream_size,
            created: filetime_or_none(self.creation_time),
            modified: filetime_or_none(self.modified_time),
        })
    }
}

/// Parses a directory stream's raw bytes (already read via [`crate::fat::read_stream_chain`])
/// into a flat list of entries, index-addressable by `child_id`/`left_sibling_id`/
/// `right_sibling_id`.
pub fn read_directory(data: &[u8]) -> ForensicResult<Vec<DirectoryEntry>> {
    ensure_format!(
        data.len() % DIRECTORY_ENTRY_SIZE == 0,
        "ole_directory",
        "directory stream size is not a multiple of the 128-byte entry size"
    );
    let mut reader = ByteReader::new(data);
    let mut entries = Vec::with_capacity(data.len() / DIRECTORY_ENTRY_SIZE);
    while !reader.is_empty() {
        let raw: DirectoryEntryRaw = reader.read_as()?;
        entries.push(raw.into_entry()?);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_bytes(name: &str, object_type: u8) -> Vec<u8> {
        let mut buf = vec![0u8; DIRECTORY_ENTRY_SIZE];
        let utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        buf[..utf16.len()].copy_from_slice(&utf16);
        let name_length = (utf16.len() + 2) as u16; // +2 for the terminating NUL the field counts
        buf[64..66].copy_from_slice(&name_length.to_le_bytes());
        buf[66] = object_type;
        buf[68..72].copy_from_slice(&crate::consts::NOSTREAM.to_le_bytes()); // left sibling
        buf[72..76].copy_from_slice(&crate::consts::NOSTREAM.to_le_bytes()); // right sibling
        buf[76..80].copy_from_slice(&crate::consts::NOSTREAM.to_le_bytes()); // child
        buf
    }

    #[test]
    fn decodes_a_root_entry_name() {
        let bytes = entry_bytes("Root Entry", 5);
        let entries = read_directory(&bytes).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Root Entry");
        assert!(matches!(entries[0].object_type, ObjectType::RootStorage));
    }

    #[test]
    fn an_unused_slot_with_zero_name_length_does_not_panic() {
        let mut bytes = vec![0u8; DIRECTORY_ENTRY_SIZE];
        bytes[64..66].copy_from_slice(&0u16.to_le_bytes());
        bytes[68..72].copy_from_slice(&crate::consts::NOSTREAM.to_le_bytes());
        bytes[72..76].copy_from_slice(&crate::consts::NOSTREAM.to_le_bytes());
        bytes[76..80].copy_from_slice(&crate::consts::NOSTREAM.to_le_bytes());
        let entries = read_directory(&bytes).unwrap();
        assert_eq!(entries[0].name, "");
        assert!(matches!(entries[0].object_type, ObjectType::Unallocated));
    }

    #[test]
    fn rejects_an_oversized_name_length_instead_of_underflowing() {
        let mut bytes = entry_bytes("x", 2);
        bytes[64..66].copy_from_slice(&200u16.to_le_bytes());
        assert!(read_directory(&bytes).is_err());
    }

    #[test]
    fn rejects_a_directory_length_that_is_not_a_multiple_of_the_entry_size() {
        let bytes = vec![0u8; DIRECTORY_ENTRY_SIZE + 1];
        assert!(read_directory(&bytes).is_err());
    }

    #[test]
    fn a_zero_filetime_decodes_to_none_not_the_1601_epoch() {
        let bytes = entry_bytes("s", 2); // creation/modified left as zero bytes
        let entries = read_directory(&bytes).unwrap();
        assert!(entries[0].created.is_none());
        assert!(entries[0].modified.is_none());
    }

    #[test]
    fn a_nonzero_filetime_decodes_to_a_real_instant() {
        let mut bytes = entry_bytes("s", 2);
        // 116444736000000000 = 1970-01-01 00:00:00 UTC in 100ns ticks since 1601-01-01.
        let epoch_filetime: u64 = 116_444_736_000_000_000;
        bytes[100..108].copy_from_slice(&epoch_filetime.to_le_bytes()); // creation_time
        bytes[108..116].copy_from_slice(&epoch_filetime.to_le_bytes()); // modified_time
        let entries = read_directory(&bytes).unwrap();
        let created = entries[0].created.expect("nonzero filetime must decode");
        assert_eq!(
            created,
            ForensicTimestamp::from_win_filetime(epoch_filetime)
        );
    }

    #[test]
    fn is_stream_and_is_storage_classify_object_types() {
        let stream = entry_bytes("s", 2);
        let storage = entry_bytes("d", 1);
        let root = entry_bytes("r", 5);
        assert!(read_directory(&stream).unwrap()[0].is_stream());
        assert!(!read_directory(&stream).unwrap()[0].is_storage());
        assert!(read_directory(&storage).unwrap()[0].is_storage());
        assert!(read_directory(&root).unwrap()[0].is_storage());
    }

    #[test]
    fn clsid_string_is_none_for_an_all_zero_clsid() {
        let bytes = entry_bytes("r", 5);
        let entries = read_directory(&bytes).unwrap();
        assert!(entries[0].clsid_string().is_none());
    }
}
