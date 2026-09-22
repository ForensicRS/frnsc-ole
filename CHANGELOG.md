# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A typed document view on top of the raw container, reachable via `OleFile::document()`
  (built lazily, cached thereafter): `OleDocument`, with
  - Document-format identification (`OleFormat`/`FormatIdentity`/`FormatEvidence`) from the
    root storage's CLSID, with a stream-name-based fallback and an explicit
    `clsid_conflicts_with_streams` flag when the two signals disagree. Recognizes Word 97,
    Excel 97, PowerPoint 97, Windows Installer packages, and Outlook messages.
  - [MS-OLEPS] property-set parsing (`oleps` module): `SummaryInformation`,
    `DocumentSummaryInformation`, and the Windows Installer's own repurposed
    `MsiSummaryInformation` projection over the same stream, plus user-defined properties via
    the section's name dictionary. CP1252 and UTF-8 code pages are decoded; every other
    declared code page decodes honestly to `AnsiString::Undecodable` rather than mangling the
    bytes. Every property is addressed independently by its own absolute offset, so one
    malformed or unrecognized-type property never costs the rest of the section.
  - `EncryptionState` (`NotEncrypted`/`Encrypted`/`NotChecked`) -- currently always
    `NotChecked`, since detection lands alongside Word text extraction in a later phase. Never
    silently reported as "not encrypted".
  - `OleFile::attributes()` now also reports `ole.document_type`, `ole.author`,
    `ole.last_saved_by`, `ole.title`, `ole.template`, `ole.application_name`, `ole.revision`,
    `ole.company`, `ole.created`, `ole.last_saved`, `ole.last_printed`, and `ole.encryption`
    when the document view resolves them.

### Fixed

- `VirtualFile::metadata()` for an OLE stream/storage no longer reports a fabricated
  `MacbTimes::default()`. Directory-entry creation/modification FILETIMEs are now parsed and
  routed through `DirectoryEntry::macb()`, and remain `None` when the on-disk FILETIME is zero
  (which [MS-CFB] 2.6.1 mandates for stream objects) rather than being mapped to the
  1601-01-01 epoch that value would otherwise decode to.
- `attributes()`'s `ole.root_clsid` was a Rust `{:02x?}` byte-array debug dump
  (`[06, 09, 02, 00, ...]`), not a GUID. It is now rendered as the canonical mixed-endian GUID
  string (`{00020906-0000-0000-C000-000000000046}`), and the key is omitted entirely for an
  all-zero (null) CLSID instead of rendering `{00000000-...}` as if it meant something.
- `OleFormatFactory::mount` unconditionally read the whole file into memory regardless of
  `Limits::materialize_in_memory_limit`. It now refuses (rather than truncating or silently
  proceeding) when the container exceeds the configured budget, and attaches the evidence
  locator to every parse error via `.with_path(..)`.

### Changed

- **Breaking:** `StructuredObject::children()` on `OleFile` now also reports storages, as
  `(LocatorSegment::Stream(path), MountKind::Object)` — previously only streams
  (`MountKind::File`) were reachable, so a storage-only consumer would see nothing. Code that
  counted `children()` will see more entries; `OleFile::stream_names()` is unaffected (it
  already filtered to streams).
- **Breaking:** `OleFile::read_stream` now returns an error when given a storage's path (it
  previously fell through to a "no stream" miss with no distinction from a genuinely absent
  path).
- `OleFormatFactory::probe` now distinguishes "has the 8-byte CFBF magic" (`ProbeScore::Strong`
  — magic bytes alone can collide) from "has the magic *and* a structurally valid header"
  (`ProbeScore::Exact`).

### Added

- `DirectoryEntry::{created, modified}: Option<ForensicTimestamp>`, plus `macb()`,
  `clsid_string()`, `is_stream()`, `is_storage()`.
- `Header::minor_version` (previously read off the wire and discarded).
- `OleFile` accessors: `entries()`, `entry(path)`, `root_entry()`, `paths()`, `storage_names()`,
  `children_of(storage)`, `stream_count()`, `storage_count()`, `unallocated_entries()`,
  `root_clsid()`, `read_stream_with_allocation(path)`.
- `attributes()` now reports the full container summary (`ole.major_version`,
  `ole.minor_version`, `ole.sector_size`, `ole.mini_sector_size`,
  `ole.mini_stream_cutoff_size`, `ole.byte_order`, `ole.total_size`,
  `ole.directory_entry_count`, `ole.stream_count`, `ole.storage_count`,
  `ole.unallocated_entry_count`, `ole.root_clsid`, `ole.root_entry_size`, `ole.root_created`,
  `ole.root_modified`) instead of 3 keys. A key is always omitted, never zero-filled, when the
  underlying value is absent.

## [0.1.0]

- Initial implementation of `StructuredObject`/`FormatFactory` for OLE Compound File Binary
  Format (CFBF) containers: header, DIFAT/FAT, mini-FAT, directory entries, and the
  child/sibling red-black tree resolved into `"Storage/Stream"` paths.
