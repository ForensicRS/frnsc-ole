//! [`OleFile`]: a parsed CFBF container, exposed to the rest of `forensic-rs` as a
//! [`StructuredObject`] — the "embedding" relationship [`forensic_rs::traits::format`]'s own
//! docs name an OLE compound file as the example of (a container exposing typed child streams,
//! as opposed to a nested filesystem or a reinterpretation of the same bytes).

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::OnceLock;

use forensic_rs::ensure_format;
use forensic_rs::prelude::*;
use forensic_rs::traits::vfs::VMetadata;

use crate::directory::{self, DirectoryEntry, ObjectType};
use crate::document::OleDocument;
use crate::fat::{self, build_fat};
use crate::header::Header;
use crate::minifat;
use crate::tree;

/// A parsed CFBF container. Holds the whole file in memory — CFBF containers in forensic
/// practice (`.msi`, legacy Office documents, embedded OLE objects) are file-sized, not
/// volume-sized, so this trades a bounded amount of memory for never needing to re-open or
/// re-seek the original source while resolving sector chains.
pub struct OleFile {
    data: Vec<u8>,
    header: Header,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    mini_stream: Vec<u8>,
    entries: Vec<DirectoryEntry>,
    /// Every reachable stream's *and* storage's full path, keyed to its index in `entries`.
    /// See [`tree::build_paths`].
    paths: BTreeMap<String, usize>,
    /// The typed document view, built lazily on first access via [`Self::document`] and cached
    /// from then on. `OnceLock` rather than eager construction in [`Self::parse`] so a caller
    /// that only wants raw streams never pays for property-set/format decoding it doesn't use.
    document: OnceLock<OleDocument>,
}

impl OleFile {
    /// Parses a complete in-memory CFBF file.
    pub fn parse(data: Vec<u8>) -> ForensicResult<Self> {
        let header = Header::parse(&data)?;
        let fat_table = build_fat(&data, &header)?;

        let directory_bytes = match header.first_directory_sector {
            Some(start) => fat::read_stream_chain(&data, &fat_table, start, header.sector_size)?,
            None => Vec::new(),
        };
        let entries = directory::read_directory(&directory_bytes)?;
        ensure_format!(!entries.is_empty(), "ole_directory", "directory stream is empty");

        let root = &entries[0];
        let mini_stream = if root.stream_size > 0 {
            fat::read_stream_chain(&data, &fat_table, root.start_sector, header.sector_size)?
        } else {
            Vec::new()
        };
        let mini_fat = minifat::build_mini_fat(&data, &fat_table, &header)?;
        let paths = tree::build_paths(&entries)?;

        Ok(Self {
            data,
            header,
            fat: fat_table,
            mini_fat,
            mini_stream,
            entries,
            paths,
            document: OnceLock::new(),
        })
    }

    /// The typed document view over this container: property sets, format identification, and
    /// (as later phases land) VBA macros, embedded objects, and Word text. Built on first
    /// access and cached from then on.
    pub fn document(&self) -> &OleDocument {
        self.document.get_or_init(|| {
            let top_level: Vec<&str> = self
                .children_of("")
                .into_iter()
                .filter(|(_, kind)| matches!(kind, ObjectType::Stream))
                .map(|(name, _)| name)
                .collect();
            OleDocument::build(self, &self.entries[0], &top_level)
        })
    }

    /// Every stream's full `"Storage/Stream"` path, in a stable (sorted) order. Storages are
    /// excluded — see [`Self::storage_names`] and [`Self::paths`] for those.
    pub fn stream_names(&self) -> impl Iterator<Item = &str> {
        self.paths
            .iter()
            .filter(|&(_, &idx)| self.entries[idx].is_stream())
            .map(|(path, _)| path.as_str())
    }

    /// Every storage's full path, in a stable (sorted) order. Does not include the (unnamed)
    /// root storage itself.
    pub fn storage_names(&self) -> impl Iterator<Item = &str> {
        self.paths
            .iter()
            .filter(|&(_, &idx)| self.entries[idx].is_storage())
            .map(|(path, _)| path.as_str())
    }

    /// Every reachable path (stream or storage) alongside its [`ObjectType`], in a stable
    /// (sorted) order.
    pub fn paths(&self) -> impl Iterator<Item = (&str, ObjectType)> {
        self.paths.iter().map(|(path, &idx)| (path.as_str(), self.entries[idx].object_type))
    }

    /// The full, flat directory-entry list, in on-disk order (index 0 is always the root
    /// storage). Includes unallocated slots — see [`Self::unallocated_entries`] to filter to
    /// just those.
    pub fn entries(&self) -> &[DirectoryEntry] {
        &self.entries
    }

    /// Looks up one entry by its full path (stream or storage).
    pub fn entry(&self, path: &str) -> Option<&DirectoryEntry> {
        self.paths.get(path).map(|&idx| &self.entries[idx])
    }

    /// Looks up an entry's directory index by its full path (stream or storage). The index
    /// twin of [`Self::entry`], for a caller (e.g. [`crate::filesystem::OleFileSystem`]) that
    /// needs to cross-reference other per-index bookkeeping it keeps outside `OleFile` itself.
    pub fn path_index(&self, path: &str) -> Option<usize> {
        self.paths.get(path).copied()
    }

    /// The root storage's own entry (always present — [`Self::parse`] rejects an empty
    /// directory stream).
    pub fn root_entry(&self) -> &DirectoryEntry {
        &self.entries[0]
    }

    /// One level of a storage's immediate children (streams and storages directly inside it,
    /// not nested further), as `(path, object_type)` pairs. `storage` is `""` for the root.
    pub fn children_of(&self, storage: &str) -> Vec<(&str, ObjectType)> {
        self.paths
            .iter()
            .filter(|(path, _)| {
                let Some(rest) = path.strip_prefix(storage) else { return false };
                let rest = if storage.is_empty() { path.as_str() } else { rest.strip_prefix('/').unwrap_or(rest) };
                !rest.is_empty() && !rest.contains('/')
            })
            .map(|(path, &idx)| (path.as_str(), self.entries[idx].object_type))
            .collect()
    }

    pub fn stream_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_stream()).count()
    }

    /// Number of *nested* storages reachable via [`Self::storage_names`]/[`Self::children_of`]
    /// — i.e. excludes the root storage itself, which has no path entry of its own (it is the
    /// implicit "" root that every path is relative to, and is already reported separately via
    /// `ole.root_clsid`/`ole.root_created`/`ole.root_modified`). This keeps `ole.storage_count`
    /// equal to what a caller actually finds by enumerating storages, rather than being off by
    /// one relative to it.
    pub fn storage_count(&self) -> usize {
        self.paths.values().filter(|&&idx| self.entries[idx].is_storage()).count()
    }

    /// Directory entries in unused/free slots — [MS-CFB] 2.6.1 `ObjectType::Unallocated`. These
    /// are not linked into the red-black tree and so are never reachable via [`Self::paths`],
    /// but a slot that still carries a non-empty name, CLSID, or size is the residual metadata
    /// of a *deleted* stream or storage — recoverable evidence, not padding.
    pub fn unallocated_entries(&self) -> impl Iterator<Item = (usize, &DirectoryEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.object_type, ObjectType::Unallocated) && !e.name.is_empty())
    }

    /// Reads a stream's bytes by its full path, resolved through the regular FAT or the
    /// mini-FAT depending on the stream's declared size relative to
    /// `mini_stream_cutoff_size` — exactly the distinction the original proof-of-concept never
    /// implemented (mini-FAT streams weren't handled at all).
    pub fn read_stream(&self, path: &str) -> ForensicResult<Vec<u8>> {
        let (bytes, _) = self.read_stream_with_allocation(path)?;
        Ok(bytes)
    }

    /// As [`Self::read_stream`], but also returns the *pre-trim* sector-chain length (the
    /// stream's real on-disk allocation, sector- or mini-sector-rounded) alongside the
    /// declared-size bytes. The difference between the two is stream slack — evidence, not
    /// waste — and is what lets [`OleStreamFile::metadata`] report `allocated_size` honestly.
    pub fn read_stream_with_allocation(&self, path: &str) -> ForensicResult<(Vec<u8>, u64)> {
        let &idx = self
            .paths
            .get(path)
            .ok_or_else(|| ForensicError::missing_data("ole_stream", CompactString::from(format!("no stream at '{path}'"))))?;
        let entry = &self.entries[idx];
        if !entry.is_stream() {
            return Err(ForensicError::invalid_format(
                "ole_stream",
                format!("'{path}' is a storage, not a stream"),
            ));
        }
        self.read_stream_by_index(idx)
    }

    fn read_stream_by_index(&self, idx: usize) -> ForensicResult<(Vec<u8>, u64)> {
        let entry = &self.entries[idx];
        let declared_size = entry.stream_size as usize;
        // [MS-CFB] 2.6.1 mandates NOSTREAM/ENDOFCHAIN as the starting sector for a genuinely
        // empty stream, which `follow_chain`'s own early exit already handles -- but a
        // non-compliant writer (or a hand-built fixture) can leave `start_sector` at some other
        // value even when the declared size is 0. Short-circuit on declared size alone rather
        // than trusting `start_sector` to be well-formed: there is nothing to read regardless of
        // what it says, and walking it needlessly risks an out-of-range/cycle error over a
        // stream that is, by its own declared size, empty.
        if declared_size == 0 {
            return Ok((Vec::new(), 0));
        }
        let raw = if entry.stream_size as usize >= self.header.mini_stream_cutoff_size {
            fat::read_stream_chain(&self.data, &self.fat, entry.start_sector, self.header.sector_size)?
        } else {
            minifat::read_mini_chain(&self.mini_stream, &self.mini_fat, entry.start_sector)?
        };
        let allocated = raw.len() as u64;
        // The last sector in a chain is padded up to a whole sector; trim back to the
        // directory entry's own declared (exact) size rather than exposing the padding.
        let bytes = if raw.len() > declared_size { raw[..declared_size].to_vec() } else { raw };
        Ok((bytes, allocated))
    }

    /// Renders the root storage's CLSID as a canonical GUID string, or `None` when it is
    /// null (no class assigned).
    pub fn root_clsid(&self) -> Option<String> {
        self.entries[0].clsid_string()
    }

    /// The validated header this container was parsed from.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// A stream's real on-disk allocation in bytes (its sector- or mini-sector-rounded chain
    /// length), **without** materializing the stream's content -- unlike
    /// [`Self::read_stream_with_allocation`], which must read every sector to return the bytes
    /// anyway. This is what lets a per-entry `metadata()` call (as `FileSystem::metadata` is,
    /// once per directory entry during a walk) report allocation/slack honestly without making
    /// the walk itself O(total stream bytes).
    pub fn stream_allocation(&self, path: &str) -> ForensicResult<u64> {
        let &idx = self
            .paths
            .get(path)
            .ok_or_else(|| ForensicError::missing_data("ole_stream", CompactString::from(format!("no stream at '{path}'"))))?;
        self.stream_allocation_by_index(idx)
    }

    pub(crate) fn stream_allocation_by_index(&self, idx: usize) -> ForensicResult<u64> {
        let entry = &self.entries[idx];
        // Same short-circuit as `read_stream_by_index`, and for the same reason: a declared
        // size of 0 means nothing to walk, regardless of what `start_sector` says.
        if entry.stream_size == 0 {
            return Ok(0);
        }
        if entry.stream_size as usize >= self.header.mini_stream_cutoff_size {
            let sectors = crate::chain::count_chain(&self.fat, entry.start_sector)?;
            Ok(sectors * self.header.sector_size as u64)
        } else {
            let sectors = crate::chain::count_chain(&self.mini_fat, entry.start_sector)?;
            Ok(sectors * crate::consts::MINI_SECTOR_SIZE as u64)
        }
    }

    /// Lazy, subtree-scoped twin of [`Self::children_of`]: `children_of` re-scans every path in
    /// the container on each call (O(total paths)), which makes a full walk over a large,
    /// possibly adversarial container O(n²). For a non-root `storage`, this walks only the
    /// `BTreeMap` range under it instead, borrowing `&self` rather than collecting. The root
    /// case (`storage == ""`) has no such prefix to range on -- top-level entries are bare names
    /// with nothing distinguishing their sort position from anything nested deeper -- so it
    /// still scans every path, exactly as `children_of("")` already does; no regression, just no
    /// extra win there.
    pub fn children_iter(&self, storage: &str) -> impl Iterator<Item = (&str, ObjectType)> {
        // Every key under `storage` starts with `"{storage}/"`; `/` (0x2F) sorts immediately
        // below `0` (0x30), so `"{storage}/".."{storage}0"` is a tight, always-correct bound
        // regardless of what characters follow within the subtree (compared byte-for-byte,
        // "{storage}/X" < "{storage}0" holds at the very next position no matter what X is).
        let (start, end): (String, String) =
            if storage.is_empty() { (String::new(), String::new()) } else { (format!("{storage}/"), format!("{storage}0")) };
        let bounded = !storage.is_empty();
        self.paths
            .range(start..)
            .take_while(move |(path, _)| !bounded || path.as_str() < end.as_str())
            .filter_map(move |(path, &idx)| {
                let rest = if storage.is_empty() { path.as_str() } else { path.strip_prefix(storage)?.strip_prefix('/')? };
                if rest.is_empty() || rest.contains('/') {
                    None
                } else {
                    Some((path.as_str(), self.entries[idx].object_type))
                }
            })
    }
}

/// Inserts `key` only when `value` is `Some` -- the crate-wide rule that an absent fact is an
/// omitted key, never a zero-filled or empty one.
fn insert_text(attrs: &mut BTreeMap<Text, Field>, key: &'static str, value: &Option<String>) {
    if let Some(v) = value {
        attrs.insert(Text::Borrowed(key), Field::Text(Text::Owned(v.clone())));
    }
}

impl StructuredObject for OleFile {
    fn kind(&self) -> &'static str {
        "ole"
    }

    /// Every reachable stream *and* storage, path-flat. `LocatorSegment` has no notion of a
    /// storage distinct from a stream, and its own doc already calls `Stream` "an
    /// alternate/NTFS/OLE named stream" — so a storage's full `"A/B"` path is carried in that
    /// same variant, distinguished only by `MountKind::Object` (a thing with children) instead
    /// of `MountKind::File` (bytes). This is the only pairing in `MountKind` that draws that
    /// distinction, and it is exactly the constraint [`open_child`](Self::open_child) matches:
    /// a consumer must be able to open every entry `children()` hands it, including a storage,
    /// which has no bytes of its own but is not an error to "open" — it opens as an empty
    /// directory-typed file.
    fn children(&self) -> ForensicResult<Vec<(LocatorSegment, MountKind)>> {
        Ok(self
            .paths
            .iter()
            .map(|(path, &idx)| {
                let kind = if self.entries[idx].is_storage() { MountKind::Object } else { MountKind::File };
                (LocatorSegment::Stream(CompactString::from(path.as_str())), kind)
            })
            .collect())
    }

    fn open_child(&self, segment: &LocatorSegment) -> ForensicResult<Box<dyn VirtualFile>> {
        let LocatorSegment::Stream(name) = segment else {
            return Err(ForensicError::invalid_format(
                "ole_stream",
                "an OLE stream is addressed by LocatorSegment::Stream",
            ));
        };
        let &idx = self.paths.get(name.as_str()).ok_or_else(|| {
            ForensicError::missing_data("ole_stream", CompactString::from(format!("no entry at '{name}'")))
        })?;
        let entry = &self.entries[idx];
        if entry.is_storage() {
            return Ok(Box::new(OleStreamFile::storage(idx, entry)));
        }
        let (bytes, allocated) = self.read_stream_by_index(idx)?;
        Ok(Box::new(OleStreamFile::stream(bytes, allocated, idx, entry)))
    }

    fn attributes(&self) -> BTreeMap<Text, Field> {
        let mut attrs = BTreeMap::new();
        attrs.insert(Text::Borrowed("ole.major_version"), Field::U64(self.header.major_version as u64));
        attrs.insert(Text::Borrowed("ole.minor_version"), Field::U64(self.header.minor_version as u64));
        attrs.insert(Text::Borrowed("ole.sector_size"), Field::U64(self.header.sector_size as u64));
        attrs.insert(Text::Borrowed("ole.mini_sector_size"), Field::U64(crate::consts::MINI_SECTOR_SIZE as u64));
        attrs.insert(
            Text::Borrowed("ole.mini_stream_cutoff_size"),
            Field::U64(self.header.mini_stream_cutoff_size as u64),
        );
        attrs.insert(Text::Borrowed("ole.byte_order"), Field::Text(Text::Borrowed("little-endian")));
        attrs.insert(Text::Borrowed("ole.total_size"), Field::U64(self.data.len() as u64));
        attrs.insert(Text::Borrowed("ole.directory_entry_count"), Field::U64(self.entries.len() as u64));
        attrs.insert(Text::Borrowed("ole.stream_count"), Field::U64(self.stream_count() as u64));
        attrs.insert(Text::Borrowed("ole.storage_count"), Field::U64(self.storage_count() as u64));
        attrs.insert(
            Text::Borrowed("ole.unallocated_entry_count"),
            Field::U64(self.unallocated_entries().count() as u64),
        );
        if let Some(clsid) = self.root_clsid() {
            attrs.insert(Text::Borrowed("ole.root_clsid"), Field::Text(Text::Owned(clsid)));
        }
        attrs.insert(Text::Borrowed("ole.root_entry_size"), Field::U64(self.entries[0].stream_size));
        if let Some(created) = self.entries[0].created {
            attrs.insert(Text::Borrowed("ole.root_created"), Field::Date(created));
        }
        if let Some(modified) = self.entries[0].modified {
            attrs.insert(Text::Borrowed("ole.root_modified"), Field::Date(modified));
        }

        let doc = self.document();
        attrs.insert(Text::Borrowed("ole.document_type"), Field::Text(Text::Owned(doc.format().format.to_string())));
        if let Some(summary) = doc.summary_information() {
            insert_text(&mut attrs, "ole.author", &summary.author);
            insert_text(&mut attrs, "ole.last_saved_by", &summary.last_saved_by);
            insert_text(&mut attrs, "ole.title", &summary.title);
            insert_text(&mut attrs, "ole.template", &summary.template);
            insert_text(&mut attrs, "ole.application_name", &summary.application_name);
            insert_text(&mut attrs, "ole.revision", &summary.revision_number);
            if let Some(created) = summary.created {
                attrs.insert(Text::Borrowed("ole.created"), Field::Date(created));
            }
            if let Some(last_saved) = summary.last_saved {
                attrs.insert(Text::Borrowed("ole.last_saved"), Field::Date(last_saved));
            }
            if let Some(last_printed) = summary.last_printed {
                attrs.insert(Text::Borrowed("ole.last_printed"), Field::Date(last_printed));
            }
        }
        if let Some(doc_summary) = doc.document_summary_information() {
            insert_text(&mut attrs, "ole.company", &doc_summary.company);
        }
        match doc.encryption() {
            crate::crypto::EncryptionState::NotEncrypted => {
                attrs.insert(Text::Borrowed("ole.is_encrypted"), Field::U64(0));
                attrs.insert(Text::Borrowed("ole.encryption"), Field::Text(Text::Borrowed("none")));
            }
            crate::crypto::EncryptionState::Encrypted { scheme, .. } => {
                attrs.insert(Text::Borrowed("ole.is_encrypted"), Field::U64(1));
                attrs.insert(Text::Borrowed("ole.encryption"), Field::Text(Text::Owned(scheme.clone())));
            }
            // Deliberately no `ole.is_encrypted` here: "unchecked" is not the same claim as
            // "confirmed not encrypted", and a boolean field cannot express the difference.
            crate::crypto::EncryptionState::NotChecked { .. } => {
                attrs.insert(Text::Borrowed("ole.encryption"), Field::Text(Text::Borrowed("not_checked")));
            }
        }
        attrs
    }
}

/// A trivial in-memory [`VirtualFile`] handed back by [`OleFile::open_child`] and by
/// [`crate::filesystem::OleFileSystem::open`]: either one stream's already-materialized bytes,
/// or a storage's zero-length placeholder. Carries the directory entry's real MACB times and
/// allocation size rather than fabricating them.
pub(crate) struct OleStreamFile {
    cursor: Cursor<Vec<u8>>,
    metadata: VMetadata,
}

impl OleStreamFile {
    pub(crate) fn stream(bytes: Vec<u8>, allocated: u64, idx: usize, entry: &DirectoryEntry) -> Self {
        let size = bytes.len() as u64;
        let metadata = VMetadata {
            file_type: VFileType::File,
            size,
            allocated_size: if allocated != size { Some(allocated) } else { None },
            times: entry.macb(),
            id: Some(FileId::from_raw(idx as u128)),
            attributes: FileAttributes::empty(),
        };
        Self { cursor: Cursor::new(bytes), metadata }
    }

    pub(crate) fn storage(idx: usize, entry: &DirectoryEntry) -> Self {
        let metadata = VMetadata {
            file_type: VFileType::Directory,
            size: 0,
            allocated_size: None,
            times: entry.macb(),
            id: Some(FileId::from_raw(idx as u128)),
            attributes: FileAttributes::DIRECTORY,
        };
        Self { cursor: Cursor::new(Vec::new()), metadata }
    }
}

impl Read for OleStreamFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(buf)
    }
}

impl Seek for OleStreamFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.cursor.seek(pos)
    }
}

impl VirtualFile for OleStreamFile {
    fn metadata(&self) -> ForensicResult<VMetadata> {
        Ok(self.metadata.clone())
    }
}

/// Test-only helper shared with [`crate::factory`]'s tests, which also need a minimal valid
/// CFBF byte buffer to exercise `OleFile::parse` end-to-end without needing a real-world fixture.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// A hand-built `DirectoryEntry` for synthetic directory-tree tests, shared across this
    /// crate's test modules.
    pub(crate) fn entry(name: &str, object_type: ObjectType, left: u32, right: u32, child: u32) -> DirectoryEntry {
        DirectoryEntry {
            name: name.to_string(),
            object_type,
            left_sibling_id: left,
            right_sibling_id: right,
            child_id: child,
            clsid: [0; 16],
            start_sector: 0,
            stream_size: 0,
            created: None,
            modified: None,
        }
    }

    /// Builds an `OleFile` directly from a hand-built entry list, bypassing `parse()` entirely
    /// -- for exercising path/tree/filesystem logic against a synthetic directory without
    /// constructing real sector chains. Shared across this crate's test modules (`ole::tests`,
    /// `filesystem::tests`, ...), all of which need this exact same private-field construction
    /// and none of which can do it themselves from outside the `ole` module.
    pub(crate) fn build_from_entries(entries: Vec<DirectoryEntry>) -> OleFile {
        let paths = tree::build_paths(&entries).unwrap();
        OleFile {
            data: vec![0u8; 4096],
            header: Header {
                major_version: 3,
                minor_version: 0,
                sector_size: 512,
                mini_stream_cutoff_size: 4096,
                first_directory_sector: None,
                first_mini_fat_sector: None,
                first_difat_sector: None,
                num_difat_sectors: 0,
                difat: [0u32; crate::consts::HEADER_DIFAT_ENTRIES],
            },
            fat: Vec::new(),
            mini_fat: Vec::new(),
            mini_stream: Vec::new(),
            entries,
            paths,
            document: OnceLock::new(),
        }
    }

    /// Builds the smallest possible valid CFBF file: a 512-byte-sector header, one FAT sector,
    /// one directory sector holding just the Root Entry (no streams). Used to exercise
    /// [`super::OleFile::parse`] end-to-end without needing a real-world fixture.
    pub(crate) fn minimal_ole_bytes() -> Vec<u8> {
        use crate::consts::{ENDOFCHAIN, FREESECT, HEADER_DIFAT_ENTRIES, HEADER_SIZE, OLE_SIGNATURE};

        // Layout: [header][FAT sector = sector 0][directory sector = sector 1]
        let mut data = vec![0u8; HEADER_SIZE + 512 * 2];

        // --- header ---
        data[0..8].copy_from_slice(&OLE_SIGNATURE);
        data[26..28].copy_from_slice(&3u16.to_le_bytes()); // major_version
        data[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes()); // byte_order
        data[30..32].copy_from_slice(&0x0009u16.to_le_bytes()); // sector_shift (512)
        data[32..34].copy_from_slice(&0x0006u16.to_le_bytes()); // mini_sector_shift (64)
        data[48..52].copy_from_slice(&1u32.to_le_bytes()); // first_directory_sector = 1
        data[56..60].copy_from_slice(&4096u32.to_le_bytes()); // mini_stream_cutoff_size
        data[60..64].copy_from_slice(&ENDOFCHAIN.to_le_bytes()); // first_mini_fat_sector
        data[68..72].copy_from_slice(&ENDOFCHAIN.to_le_bytes()); // first_difat_sector
        // difat[0] = 0 (sector 0 holds the FAT); the rest are FREESECT
        let difat_start = 76;
        for i in 0..HEADER_DIFAT_ENTRIES {
            let value = if i == 0 { 0u32 } else { FREESECT };
            data[difat_start + i * 4..difat_start + i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }

        // --- FAT sector (sector 0, right after the header) ---
        let fat_sector_start = HEADER_SIZE;
        // sector 0 (itself, the FAT) -> FATSECT marker
        data[fat_sector_start..fat_sector_start + 4].copy_from_slice(&crate::consts::FATSECT.to_le_bytes());
        // sector 1 (the directory) -> ENDOFCHAIN
        data[fat_sector_start + 4..fat_sector_start + 8].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        for i in 2..(512 / 4) {
            data[fat_sector_start + i * 4..fat_sector_start + i * 4 + 4].copy_from_slice(&FREESECT.to_le_bytes());
        }

        // --- directory sector (sector 1) : one Root Entry, rest unallocated ---
        let dir_sector_start = HEADER_SIZE + 512;
        let name = "Root Entry";
        let utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        data[dir_sector_start..dir_sector_start + utf16.len()].copy_from_slice(&utf16);
        let name_length = (utf16.len() + 2) as u16;
        data[dir_sector_start + 64..dir_sector_start + 66].copy_from_slice(&name_length.to_le_bytes());
        data[dir_sector_start + 66] = 5; // RootStorage
        data[dir_sector_start + 68..dir_sector_start + 72].copy_from_slice(&crate::consts::NOSTREAM.to_le_bytes());
        data[dir_sector_start + 72..dir_sector_start + 76].copy_from_slice(&crate::consts::NOSTREAM.to_le_bytes());
        data[dir_sector_start + 76..dir_sector_start + 80].copy_from_slice(&crate::consts::NOSTREAM.to_le_bytes());
        // start_sector (offset 116) / stream_size (offset 120) left as 0 -> empty mini stream

        data
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::minimal_ole_bytes;
    use super::*;

    #[test]
    fn parses_a_minimal_valid_file_with_no_streams() {
        let ole = OleFile::parse(minimal_ole_bytes()).unwrap();
        assert_eq!(ole.stream_names().count(), 0);
    }

    #[test]
    fn reading_a_missing_stream_is_an_error_not_a_panic() {
        let ole = OleFile::parse(minimal_ole_bytes()).unwrap();
        assert!(ole.read_stream("does not exist").is_err());
    }

    #[test]
    fn a_zero_size_stream_reads_as_empty_regardless_of_a_stray_start_sector() {
        // [MS-CFB] 2.6.1 mandates NOSTREAM/ENDOFCHAIN as a zero-length stream's start_sector,
        // but a non-compliant writer (or a hand-built fixture, as here) can leave it at some
        // other value. Both read paths must short-circuit on the declared size alone rather
        // than attempting to walk that stray value into an empty FAT/mini-FAT table.
        let entries = vec![
            tests_support::entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            tests_support::entry("Empty", ObjectType::Stream, u32::MAX, u32::MAX, u32::MAX), // start_sector defaults to 0, not NOSTREAM
        ];
        let ole = tests_support::build_from_entries(entries);
        assert_eq!(ole.read_stream("Empty").unwrap(), Vec::<u8>::new());
        assert_eq!(ole.stream_allocation("Empty").unwrap(), 0);
    }

    #[test]
    fn attributes_render_a_canonical_root_clsid_when_present() {
        let mut data = minimal_ole_bytes();
        // Stamp a non-zero CLSID onto the root entry (offset 96 within the directory sector).
        let dir_sector_start = crate::consts::HEADER_SIZE + 512;
        let clsid: [u8; 16] = [
            0x06, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        data[dir_sector_start + 80..dir_sector_start + 96].copy_from_slice(&clsid);
        let ole = OleFile::parse(data).unwrap();
        let attrs = ole.attributes();
        match attrs.get(&Text::Borrowed("ole.root_clsid")) {
            Some(Field::Text(t)) => assert_eq!(t.as_ref(), "{00020906-0000-0000-C000-000000000046}"),
            other => panic!("expected a canonical GUID string, got {other:?}"),
        }
    }

    #[test]
    fn attributes_omit_root_clsid_when_null() {
        let ole = OleFile::parse(minimal_ole_bytes()).unwrap();
        assert!(!ole.attributes().contains_key(&Text::Borrowed("ole.root_clsid")));
    }

    #[test]
    fn children_pairs_streams_with_file_and_storages_with_object() {
        // Root -> child "Storage" (Storage) -> child "Stream" (Stream)
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("Storage", ObjectType::Storage, u32::MAX, u32::MAX, 2),
            test_entry("Stream", ObjectType::Stream, u32::MAX, u32::MAX, u32::MAX),
        ];
        let paths = tree::build_paths(&entries).unwrap();
        let ole = test_ole_file(entries, paths);
        let children = ole.children().unwrap();
        let storage_kind = children
            .iter()
            .find(|(seg, _)| matches!(seg, LocatorSegment::Stream(n) if n == "Storage"))
            .map(|(_, k)| *k);
        assert_eq!(storage_kind, Some(MountKind::Object));
        let stream_kind = children
            .iter()
            .find(|(seg, _)| matches!(seg, LocatorSegment::Stream(n) if n == "Storage/Stream"))
            .map(|(_, k)| *k);
        assert_eq!(stream_kind, Some(MountKind::File));
    }

    #[test]
    fn open_child_on_a_storage_yields_a_zero_length_directory_file() {
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("Storage", ObjectType::Storage, u32::MAX, u32::MAX, u32::MAX),
        ];
        let paths = tree::build_paths(&entries).unwrap();
        let ole = test_ole_file(entries, paths);
        let file = ole.open_child(&LocatorSegment::Stream(CompactString::from("Storage"))).unwrap();
        let meta = file.metadata().unwrap();
        assert_eq!(meta.file_type, VFileType::Directory);
        assert_eq!(meta.size, 0);
    }

    #[test]
    fn children_of_lists_one_level_at_the_requested_storage() {
        // Root -> "A" (Storage, child "B") ; "A" -> "B" (Stream) ; "A" -> "C" (Storage)
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("A", ObjectType::Storage, u32::MAX, u32::MAX, 2),
            test_entry("B", ObjectType::Stream, u32::MAX, 3, u32::MAX),
            test_entry("C", ObjectType::Storage, u32::MAX, u32::MAX, u32::MAX),
        ];
        let paths = tree::build_paths(&entries).unwrap();
        let ole = test_ole_file(entries, paths);

        let root_children: Vec<&str> = ole.children_of("").iter().map(|(p, _)| *p).collect();
        assert_eq!(root_children, vec!["A"]);

        let mut a_children: Vec<&str> = ole.children_of("A").iter().map(|(p, _)| *p).collect();
        a_children.sort();
        assert_eq!(a_children, vec!["A/B", "A/C"]);
    }

    #[test]
    fn children_iter_agrees_with_children_of() {
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("A", ObjectType::Storage, u32::MAX, u32::MAX, 2),
            test_entry("B", ObjectType::Stream, u32::MAX, 3, u32::MAX),
            test_entry("C", ObjectType::Storage, u32::MAX, u32::MAX, u32::MAX),
        ];
        let paths = tree::build_paths(&entries).unwrap();
        let ole = test_ole_file(entries, paths);

        let mut root_a: Vec<&str> = ole.children_of("").iter().map(|(p, _)| *p).collect();
        let mut root_b: Vec<&str> = ole.children_iter("").map(|(p, _)| p).collect();
        root_a.sort();
        root_b.sort();
        assert_eq!(root_a, root_b);

        let mut nested_a: Vec<&str> = ole.children_of("A").iter().map(|(p, _)| *p).collect();
        let mut nested_b: Vec<&str> = ole.children_iter("A").map(|(p, _)| p).collect();
        nested_a.sort();
        nested_b.sort();
        assert_eq!(nested_a, nested_b);
        assert_eq!(nested_a, vec!["A/B", "A/C"]);
    }

    #[test]
    fn children_iter_does_not_bleed_into_a_lexicographically_adjacent_sibling() {
        // "A" and "A0" (no slash) are lexicographic neighbors of "A/..." paths; a naive prefix
        // range must not pull "A0"'s own children into "A"'s results.
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("A", ObjectType::Storage, u32::MAX, 2, 3),
            test_entry("A0", ObjectType::Storage, u32::MAX, u32::MAX, 4),
            test_entry("Inside", ObjectType::Stream, u32::MAX, u32::MAX, u32::MAX),
            test_entry("AlsoInside", ObjectType::Stream, u32::MAX, u32::MAX, u32::MAX),
        ];
        let paths = tree::build_paths(&entries).unwrap();
        let ole = test_ole_file(entries, paths);

        let a_children: Vec<&str> = ole.children_iter("A").map(|(p, _)| p).collect();
        assert_eq!(a_children, vec!["A/Inside"]);
    }

    #[test]
    fn stream_allocation_matches_read_stream_with_allocation() {
        // Real, non-synthetic coverage against a fixture with both FAT- and mini-FAT-resident
        // streams; follows the crate's fixture-skip pattern (see tests/sample_doc_fixture.rs).
        let path = std::path::Path::new("artifacts/SampleDoc.doc");
        if !path.exists() {
            println!("SKIP: fixture 'artifacts/SampleDoc.doc' unavailable");
            return;
        }
        let data = std::fs::read(path).expect("fixture exists but could not be read");
        let ole = OleFile::parse(data).unwrap();
        for path in ole.stream_names().map(str::to_string).collect::<Vec<_>>() {
            let (_, from_read) = ole.read_stream_with_allocation(&path).unwrap();
            let from_count = ole.stream_allocation(&path).unwrap();
            assert_eq!(from_read, from_count, "mismatch for stream '{path}'");
        }
    }

    #[test]
    fn unallocated_entries_surfaces_named_free_slots_but_not_empty_ones() {
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, u32::MAX),
            test_entry("DeletedStream", ObjectType::Unallocated, u32::MAX, u32::MAX, u32::MAX),
            test_entry("", ObjectType::Unallocated, u32::MAX, u32::MAX, u32::MAX),
        ];
        let paths = tree::build_paths(&entries).unwrap();
        let ole = test_ole_file(entries, paths);

        let found: Vec<(usize, &str)> = ole.unallocated_entries().map(|(idx, e)| (idx, e.name.as_str())).collect();
        assert_eq!(found, vec![(1, "DeletedStream")]);
    }

    fn test_ole_file(entries: Vec<DirectoryEntry>, paths: BTreeMap<String, usize>) -> OleFile {
        OleFile {
            data: vec![0u8; 4096],
            header: test_header(),
            fat: Vec::new(),
            mini_fat: Vec::new(),
            mini_stream: Vec::new(),
            entries,
            paths,
            document: OnceLock::new(),
        }
    }

    fn test_entry(name: &str, object_type: ObjectType, left: u32, right: u32, child: u32) -> DirectoryEntry {
        DirectoryEntry {
            name: name.to_string(),
            object_type,
            left_sibling_id: left,
            right_sibling_id: right,
            child_id: child,
            clsid: [0; 16],
            start_sector: 0,
            stream_size: 0,
            created: None,
            modified: None,
        }
    }

    fn test_header() -> Header {
        Header {
            major_version: 3,
            minor_version: 0,
            sector_size: 512,
            mini_stream_cutoff_size: 4096,
            first_directory_sector: None,
            first_mini_fat_sector: None,
            first_difat_sector: None,
            num_difat_sectors: 0,
            difat: [0u32; crate::consts::HEADER_DIFAT_ENTRIES],
        }
    }
}
