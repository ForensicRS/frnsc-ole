//! [`OleFileSystem`]: exposes a parsed CFBF container as an ordinary `forensic_rs::FileSystem`
//! -- storages are directories, streams are files -- so every generic VFS-based tool (`walk`,
//! `glob`, the bridge's `VfsProvider`, MCP resource browsing, policy enforcement via
//! `AuthorizedVirtualFileSystem`) works over an OLE document's internals with zero OLE-specific
//! code. This is the crate's primary integration surface; [`crate::OleFile`]'s
//! `StructuredObject` implementation is kept for the embedding relationship but is no longer the
//! main way to reach a document's contents.
//!
//! Two things this module exists to get right, both because `forensic_rs::core::path::FPath`
//! has real-filesystem semantics that CFBF's own naming rules don't guarantee:
//!
//! - **Name sanitization** ([MS-CFB] 2.6.1 forbids `/ \ : !` in a name; `FPath` treats `/`/`\`
//!   as separators and `X:` as a drive). A name containing one is simultaneously a spec
//!   violation and a path-confusion vector, so it is excluded from this filesystem's surface
//!   entirely -- never rejecting the whole mount, never escaping the name -- and reported via
//!   [`OleFileSystem::name_anomalies`]. See [`crate::names`].
//! - **Case sensitivity.** [MS-CFB] 2.6.4 orders sibling directory entries by uppercase-mapped
//!   name, so two entries differing only by case are, per the format itself, the same entry.
//!   [`OleFileSystem::case_sensitivity`] reports [`CaseSensitivity::Insensitive`] accordingly,
//!   backed by an exact-match-first, then-case-folded lookup.

use std::collections::BTreeMap;
use std::sync::Arc;

use forensic_rs::core::path::Component;
use forensic_rs::prelude::*;
use forensic_rs::traits::vfs::VMetadata;

use crate::directory::DirectoryEntry;
use crate::names::{self, NameAnomaly};
use crate::ole::{OleFile, OleStreamFile};

/// What a case-folded lookup key resolves to.
enum FoldedTarget {
    /// Exactly one addressable entry folds to this key -- `(real path, directory index)`.
    Unique(String, usize),
    /// Two or more addressable entries fold to the same key ([MS-CFB] 2.6.4 forbids this, but
    /// this crate reports facts rather than assumes well-formedness). A fold lookup refuses
    /// rather than guessing; the entries remain reachable by their own exact names.
    Ambiguous,
}

/// A parsed CFBF container, addressed as a `FileSystem`. Wraps `Arc<OleFile>` rather than an
/// owned `OleFile` so the same parse backs both this view and [`OleFile`]'s own
/// `StructuredObject` view -- constructing both from the same bytes would otherwise mean parsing
/// (and, for a large container, holding in memory) the same document twice.
pub struct OleFileSystem {
    ole: Arc<OleFile>,
    /// Directory indices excluded from this filesystem's surface because their own name cannot
    /// be honestly represented as an `FPath` component, and why. Streams and storages only --
    /// the root storage has no name of its own to validate, and an `Unallocated` slot is never
    /// reachable through `OleFile::paths` in the first place.
    hidden: BTreeMap<usize, NameAnomaly>,
    folded: BTreeMap<String, FoldedTarget>,
}

impl OleFileSystem {
    pub fn new(ole: OleFile) -> Self {
        Self::from_arc(Arc::new(ole))
    }

    pub fn from_arc(ole: Arc<OleFile>) -> Self {
        let mut hidden = BTreeMap::new();
        for (idx, entry) in ole.entries().iter().enumerate() {
            if entry.is_stream() || entry.is_storage() {
                if let Some(anomaly) = names::classify(&entry.name) {
                    hidden.insert(idx, anomaly);
                }
            }
        }

        let mut folded: BTreeMap<String, FoldedTarget> = BTreeMap::new();
        for (path, _kind) in ole.paths() {
            let Some(idx) = ole.path_index(path) else { continue };
            if hidden.contains_key(&idx) {
                continue;
            }
            let key = fold_case(path);
            folded
                .entry(key)
                .and_modify(|t| *t = FoldedTarget::Ambiguous)
                .or_insert_with(|| FoldedTarget::Unique(path.to_string(), idx));
        }

        Self { ole, hidden, folded }
    }

    /// The underlying parsed container.
    pub fn ole(&self) -> &OleFile {
        &self.ole
    }

    /// The underlying parsed container's shared handle -- for a caller that wants to also build
    /// (or already holds) the `StructuredObject`/typed-document view from the same parse.
    pub fn ole_arc(&self) -> &Arc<OleFile> {
        &self.ole
    }

    /// Every directory entry excluded from this filesystem's surface because its own name
    /// cannot be honestly represented as an `FPath` component -- a [MS-CFB] 2.6.1 violation and
    /// (for the characters `FPath` treats as separators) a real path-confusion vector. These
    /// entries remain fully visible through [`OleFile::entries`]; they are simply never
    /// `open()`/`metadata()`/`read_dir()`-addressable through this `FileSystem`.
    pub fn name_anomalies(&self) -> impl Iterator<Item = (usize, &DirectoryEntry, NameAnomaly)> {
        self.hidden.iter().map(|(&idx, &anomaly)| (idx, &self.ole.entries()[idx], anomaly))
    }

    fn is_addressable(&self, idx: usize) -> bool {
        !self.hidden.contains_key(&idx)
    }

    /// Resolves an `FPath` to `(the entry's real internal path, its directory index)`. `""`
    /// denotes the root storage, which has no path entry of its own in [`OleFile::paths`] and no
    /// directory index worth reporting here -- callers special-case an empty returned path.
    fn lookup(&self, path: &FPath) -> Option<(String, usize)> {
        let key = to_internal(path);
        if key.is_empty() {
            return Some((String::new(), 0));
        }
        if let Some(idx) = self.ole.path_index(&key) {
            return self.is_addressable(idx).then_some((key, idx));
        }
        match self.folded.get(&fold_case(&key)) {
            Some(FoldedTarget::Unique(real_path, idx)) => Some((real_path.clone(), *idx)),
            _ => None,
        }
    }

    fn metadata_for(&self, real_path: &str, idx: usize) -> ForensicResult<VMetadata> {
        if idx == 0 {
            let root = self.ole.root_entry();
            return Ok(VMetadata {
                file_type: VFileType::Directory,
                size: 0,
                allocated_size: None,
                times: root.macb(),
                id: Some(FileId::from_raw(0)),
                attributes: FileAttributes::DIRECTORY,
            });
        }
        let entry = &self.ole.entries()[idx];
        if entry.is_storage() {
            return Ok(VMetadata {
                file_type: VFileType::Directory,
                size: 0,
                allocated_size: None,
                times: entry.macb(),
                id: Some(FileId::from_raw(idx as u128)),
                attributes: FileAttributes::DIRECTORY,
            });
        }
        // A stream: report allocation without materializing its bytes -- this is called once
        // per entry during a directory walk, so it must never be O(stream size).
        let declared = entry.stream_size;
        let allocated = self.ole.stream_allocation(real_path)?;
        Ok(VMetadata {
            file_type: VFileType::File,
            size: declared,
            allocated_size: if allocated != declared { Some(allocated) } else { None },
            times: entry.macb(),
            id: Some(FileId::from_raw(idx as u128)),
            attributes: FileAttributes::empty(),
        })
    }
}

/// Keeps only `Component::Normal` segments, dropping `RootDir`, `Drive`, `CurDir` and
/// `ParentDir` -- the same rule `forensic_rs::core::fs::ChRootFileSystem::resolve` applies, for
/// the same reason: nothing this returns can ever address outside the container. Two documented
/// consequences: `""`, `"/"`, `"\"`, `"."`, and `"C:"` all resolve to the root storage (nothing
/// in a CFBF container's own path space needs a leading separator or drive to begin with), and
/// `"A/../B"` resolves to `"A/B"`, not `"B"` -- `..` is dropped, not applied.
fn to_internal(path: &FPath) -> String {
    let mut out = String::new();
    for component in path.components() {
        if let Component::Normal(s) = component {
            if !out.is_empty() {
                out.push('/');
            }
            out.push_str(s);
        }
    }
    out
}

/// [MS-CFB] 2.6.4 compares directory entry names by uppercase mapping. `str::to_uppercase` is
/// full-Unicode and not byte-identical to the format's own table (e.g. German `ß` -> `"SS"`),
/// but that divergence can only ever affect the *fold fallback* -- `lookup`'s exact-match path
/// always wins first and is untouched by it.
fn fold_case(s: &str) -> String {
    s.to_uppercase()
}

impl FileSystem for OleFileSystem {
    fn open(&self, path: &FPath) -> ForensicResult<Box<dyn VirtualFile>> {
        let (real_path, idx) = self.lookup(path).ok_or_else(|| ForensicError::path_not_found(path.to_string()))?;
        if idx == 0 || self.ole.entries()[idx].is_storage() {
            let entry = if idx == 0 { self.ole.root_entry() } else { &self.ole.entries()[idx] };
            return Ok(Box::new(OleStreamFile::storage(idx, entry)));
        }
        let (bytes, allocated) = self.ole.read_stream_with_allocation(&real_path)?;
        Ok(Box::new(OleStreamFile::stream(bytes, allocated, idx, &self.ole.entries()[idx])))
    }

    fn metadata(&self, path: &FPath) -> ForensicResult<VMetadata> {
        let (real_path, idx) = self.lookup(path).ok_or_else(|| ForensicError::path_not_found(path.to_string()))?;
        self.metadata_for(&real_path, idx)
    }

    fn read_dir(&self, path: &FPath) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<DirEntry>> + '_>> {
        let (real_path, idx) = self.lookup(path).ok_or_else(|| ForensicError::path_not_found(path.to_string()))?;
        if idx != 0 && self.ole.entries()[idx].is_stream() {
            return Err(ForensicError::invalid_format("ole_filesystem", format!("'{real_path}' is a stream, not a storage")));
        }
        let entries: Vec<ForensicResult<DirEntry>> = self
            .ole
            .children_iter(&real_path)
            .filter(|(child_path, _)| {
                self.ole.path_index(child_path).is_some_and(|child_idx| self.is_addressable(child_idx))
            })
            .map(|(child_path, _kind)| {
                let child_idx = self.ole.path_index(child_path).expect("just filtered on this existing");
                let meta = self.metadata_for(child_path, child_idx)?;
                Ok(DirEntry { path: FPathBuf::from(child_path), file_type: meta.file_type, metadata: Some(meta) })
            })
            .collect();
        Ok(Box::new(entries.into_iter()))
    }

    fn source(&self) -> SourceKind {
        // Inside a fully-parsed container, an absent path genuinely does not exist -- the whole
        // file was materialized and the directory fully enumerated at parse time. A parent
        // filesystem's own incompleteness (e.g. this document came from a `Triage` collection)
        // does not propagate inward: this document itself is complete.
        SourceKind::Image
    }

    fn case_sensitivity(&self) -> CaseSensitivity {
        CaseSensitivity::Insensitive
    }

    fn as_attributes(&self) -> Option<&dyn PathAttributes> {
        Some(self)
    }
}

/// Inserts `key` only when `value` is `Some` -- the crate-wide rule (see `AGENTS.md`) that an
/// absent fact is an omitted key, never a zero-filled or empty one.
fn insert_opt<T>(attrs: &mut BTreeMap<Text, Field>, key: &'static str, value: Option<T>, to_field: impl FnOnce(T) -> Field) {
    if let Some(v) = value {
        attrs.insert(Text::Borrowed(key), to_field(v));
    }
}

impl PathAttributes for OleFileSystem {
    /// Per-path facts, layered:
    ///
    /// - **The filesystem root** (`path == ""`) gets the whole container-level map
    ///   [`OleFile::attributes`] already builds (document metadata, format identification,
    ///   encryption state, ...) verbatim, plus a handful of filesystem-layer-only keys.
    /// - **A storage** gets its own identity facts (path, name, CLSID, MACB, child count) --
    ///   deliberately *not* a repeat of the whole container map; an MSI with hundreds of streams
    ///   would otherwise replicate dozens of keys per entry for no new information.
    /// - **A stream** gets its own identity plus allocation/slack facts that only make sense
    ///   per-stream.
    ///
    /// An unknown or hidden (see [`Self::name_anomalies`]) path is still an `Err`, exactly as
    /// [`FileSystem::metadata`] reports it -- this method is never a cheaper way to probe
    /// existence than `metadata` already is.
    fn attributes(&self, path: &FPath) -> ForensicResult<BTreeMap<Text, Field>> {
        let (real_path, idx) = self.lookup(path).ok_or_else(|| ForensicError::path_not_found(path.to_string()))?;

        if idx == 0 {
            let mut attrs = self.ole.attributes();
            attrs.insert(Text::Borrowed("ole.storage.directory_index"), Field::U64(0));
            attrs.insert(
                Text::Borrowed("ole.storage.child_count"),
                Field::U64(self.ole.children_iter("").count() as u64),
            );
            if !self.hidden.is_empty() {
                attrs.insert(Text::Borrowed("ole.hidden_entry_count"), Field::U64(self.hidden.len() as u64));
            }
            return Ok(attrs);
        }

        let entry = &self.ole.entries()[idx];
        let mut attrs = BTreeMap::new();
        let leaf = real_path.rsplit('/').next().unwrap_or(&real_path);

        if entry.is_storage() {
            attrs.insert(Text::Borrowed("ole.storage.path"), Field::Text(Text::Owned(real_path.clone())));
            attrs.insert(Text::Borrowed("ole.storage.name"), Field::Text(Text::Owned(leaf.to_string())));
            attrs.insert(Text::Borrowed("ole.storage.directory_index"), Field::U64(idx as u64));
            attrs.insert(
                Text::Borrowed("ole.storage.child_count"),
                Field::U64(self.ole.children_iter(&real_path).count() as u64),
            );
            insert_opt(&mut attrs, "ole.storage.clsid", entry.clsid_string(), |v| Field::Text(Text::Owned(v)));
            insert_opt(&mut attrs, "ole.storage.created", entry.created, Field::Date);
            insert_opt(&mut attrs, "ole.storage.modified", entry.modified, Field::Date);
        } else {
            attrs.insert(Text::Borrowed("ole.stream.path"), Field::Text(Text::Owned(real_path.clone())));
            attrs.insert(Text::Borrowed("ole.stream.name"), Field::Text(Text::Owned(leaf.to_string())));
            attrs.insert(Text::Borrowed("ole.stream.size"), Field::U64(entry.stream_size));
            attrs.insert(Text::Borrowed("ole.stream.directory_index"), Field::U64(idx as u64));
            let in_mini_fat = (entry.stream_size as usize) < self.ole.header().mini_stream_cutoff_size;
            attrs.insert(Text::Borrowed("ole.stream.in_mini_fat"), Field::U64(in_mini_fat as u64));
            if let Ok(allocated) = self.ole.stream_allocation(&real_path) {
                if allocated > entry.stream_size {
                    // The common case: the last sector in the chain pads out past the declared
                    // size. The padding itself is evidence, not waste -- surfaced as slack.
                    attrs.insert(Text::Borrowed("ole.stream.allocated_size"), Field::U64(allocated));
                    attrs.insert(Text::Borrowed("ole.stream.slack_size"), Field::U64(allocated - entry.stream_size));
                } else if allocated < entry.stream_size {
                    // The chain is shorter than the entry claims -- a truncated/corrupt stream,
                    // a materially different fact from slack. Reported as its own flag rather
                    // than a "negative slack" that a naive subtraction would otherwise produce.
                    attrs.insert(Text::Borrowed("ole.stream.allocated_size"), Field::U64(allocated));
                    attrs.insert(Text::Borrowed("ole.stream.truncated"), Field::U64(1));
                }
            }
            insert_opt(&mut attrs, "ole.stream.clsid", entry.clsid_string(), |v| Field::Text(Text::Owned(v)));
            insert_opt(&mut attrs, "ole.stream.created", entry.created, Field::Date);
            insert_opt(&mut attrs, "ole.stream.modified", entry.modified, Field::Date);
        }
        Ok(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::ObjectType;
    use crate::ole::tests_support::{build_from_entries as test_ole_file, entry as test_entry};

    #[test]
    fn root_aliases_all_resolve_to_the_root_storage() {
        let entries = vec![test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, u32::MAX)];
        let fs = OleFileSystem::new(test_ole_file(entries));
        for alias in ["", "/", "\\", ".", "C:"] {
            let meta = fs.metadata(FPath::new(alias)).unwrap_or_else(|e| panic!("'{alias}' should resolve to root: {e}"));
            assert_eq!(meta.file_type, VFileType::Directory, "'{alias}'");
        }
    }

    #[test]
    fn open_and_read_dir_round_trip_a_stream_and_a_storage() {
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("Storage", ObjectType::Storage, u32::MAX, u32::MAX, 2),
            test_entry("Stream", ObjectType::Stream, u32::MAX, u32::MAX, u32::MAX),
        ];
        let fs = OleFileSystem::new(test_ole_file(entries));

        let root: Vec<String> = fs.read_dir(FPath::new("")).unwrap().map(|e| e.unwrap().path.to_string()).collect();
        assert_eq!(root, vec!["Storage"]);

        let inner: Vec<String> =
            fs.read_dir(FPath::new("Storage")).unwrap().map(|e| e.unwrap().path.to_string()).collect();
        assert_eq!(inner, vec!["Storage/Stream"]);

        let meta = fs.metadata(FPath::new("Storage")).unwrap();
        assert_eq!(meta.file_type, VFileType::Directory);
        let bytes = fs.read_all(FPath::new("Storage")).unwrap();
        assert!(bytes.is_empty(), "a storage has no bytes of its own");
    }

    #[test]
    fn read_dir_on_a_stream_errors() {
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("Stream", ObjectType::Stream, u32::MAX, u32::MAX, u32::MAX),
        ];
        let fs = OleFileSystem::new(test_ole_file(entries));
        assert!(fs.read_dir(FPath::new("Stream")).is_err());
    }

    #[test]
    fn open_a_missing_path_errors() {
        let entries = vec![test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, u32::MAX)];
        let fs = OleFileSystem::new(test_ole_file(entries));
        assert!(fs.open(FPath::new("does-not-exist")).is_err());
    }

    #[test]
    fn case_insensitive_lookup_resolves_via_the_fold_fallback() {
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("WordDocument", ObjectType::Stream, u32::MAX, u32::MAX, u32::MAX),
        ];
        let fs = OleFileSystem::new(test_ole_file(entries));
        assert!(fs.metadata(FPath::new("WordDocument")).is_ok());
        assert!(fs.metadata(FPath::new("worddocument")).is_ok(), "exact-case-insensitive per MS-CFB 2.6.4");
        assert!(fs.metadata(FPath::new("WORDDOCUMENT")).is_ok());
    }

    #[test]
    fn an_ambiguous_case_fold_refuses_rather_than_guessing() {
        // Two siblings differing only by case -- a MS-CFB 2.6.4 violation this crate reports
        // rather than assumes away. Both exact names must still resolve; only the fold shortcut
        // is refused.
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("stream", ObjectType::Stream, u32::MAX, 2, u32::MAX),
            test_entry("Stream", ObjectType::Stream, u32::MAX, u32::MAX, u32::MAX),
        ];
        let fs = OleFileSystem::new(test_ole_file(entries));
        assert!(fs.metadata(FPath::new("stream")).is_ok());
        assert!(fs.metadata(FPath::new("Stream")).is_ok());
        assert!(fs.metadata(FPath::new("STREAM")).is_err(), "ambiguous fold must not guess");
    }

    #[test]
    fn a_name_containing_a_forbidden_character_is_hidden_and_reported() {
        let entries = vec![
            test_entry("Root Entry", ObjectType::RootStorage, u32::MAX, u32::MAX, 1),
            test_entry("A/B", ObjectType::Stream, u32::MAX, u32::MAX, u32::MAX),
        ];
        let fs = OleFileSystem::new(test_ole_file(entries));

        // Never openable, never listed.
        let root: Vec<String> = fs.read_dir(FPath::new("")).unwrap().map(|e| e.unwrap().path.to_string()).collect();
        assert!(root.is_empty(), "the anomalous entry must not appear in a listing: {root:?}");

        // But visible as a reported anomaly, with the real on-disk name preserved verbatim.
        let anomalies: Vec<_> = fs.name_anomalies().collect();
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].1.name, "A/B");
        assert_eq!(anomalies[0].2, NameAnomaly::ForbiddenCharacter('/'));
    }

    #[test]
    fn send_sync_holds() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OleFileSystem>();
        assert_send_sync::<Arc<dyn FileSystem>>();
    }
}
