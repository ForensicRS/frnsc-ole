# frnsc-ole

[![crates.io](https://img.shields.io/crates/v/frnsc-ole.svg)](https://crates.io/crates/frnsc-ole)
[![docs.rs](https://docs.rs/frnsc-ole/badge.svg)](https://docs.rs/frnsc-ole)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/ForensicRS/frnsc-ole/actions/workflows/rust.yml/badge.svg)](https://github.com/ForensicRS/frnsc-ole/actions/workflows/rust.yml)

Reads OLE Compound File Binary Format (CFBF) containers — `.msi`, legacy Office documents
(`.doc`/`.xls`/`.ppt`), Outlook `.msg`, Visio/Publisher files, and other structured-storage
formats — and, on top of the container, extracts document metadata and format identification
(with VBA macro source, embedded objects, and Word plain text still to come).

**Implements:**
- `forensic_rs::FileSystem` + `forensic_rs::traits::vfs::PathAttributes` (via [`OleFileSystem`],
  mounted by `OleFileSystemFactory`) — **the primary surface.** A CFBF container's storages
  become directories and streams become files, so `walk`, `glob`, the bridge's `VfsProvider`,
  MCP resource browsing, and `AuthorizedVirtualFileSystem` policy enforcement all work over a
  document's internals with zero OLE-specific code anywhere downstream. Per-path document facts
  (author, format, allocation/slack, ...) ride the `PathAttributes` capability probe rather than
  an inherent method, so any generic tool holding `dyn FileSystem` can reach them.
- `StructuredObject` + `FormatFactory` (`Mounted::Object`, via `OleFormatFactory`) — the
  embedding relationship, for an OLE document found nested inside another format. Kept alongside
  the `FileSystem` view but no longer the primary way to reach a document's contents.

Built on [`forensic-rs`](https://github.com/ForensicRS/forensic-rs), which decouples forensic
analysis logic from data access: code written against `FileSystem`/`PathAttributes` reads the
same `.doc` whether it came from a live path, a raw disk image, a triage collection, a nested
ZIP a `MountResolver` already unpacked, or an `InMemoryVirtualFileSystem` in a test — this crate
is never named in that analysis code.

## Status & limitations

- The whole container is held in memory (`OleFile::parse(Vec<u8>)`); CFBF containers in forensic
  practice are file-sized, not volume-sized, so this trades a bounded amount of memory for never
  re-seeking the original source while resolving sector chains. Both factories refuse (rather
  than silently truncating) a file larger than `Limits::materialize_in_memory_limit`, and do
  **not** fall back to a spilled/streaming reader — see `AGENTS.md` for why that would defeat
  the budget it's enforcing.
- Only little-endian MS-CFB v3 (512-byte sectors) and v4 (4096-byte sectors) are supported, with
  64-byte mini sectors — the combination every real-world writer produces.
- Read-only. This crate never writes to evidence.
- A directory entry name containing an [MS-CFB]-forbidden character (`/ \ : !`) or equal to
  `.`/`..` is excluded from `OleFileSystem`'s surface (never listed, never opened) rather than
  rejecting the whole mount — see `OleFileSystem::name_anomalies()` and `AGENTS.md`.
- **Facts only, no scoring.** This crate extracts primitives — property values, and (as later
  phases land) macro source, embedded files, document text — and deliberately ships no malware
  detection, keyword matching, or verdicts. Build that downstream, on top of what this crate
  surfaces.

## Usage

As a `FileSystem`, from bytes you already have:

```rust
use forensic_rs::prelude::*;
use frnsc_ole::{OleFile, OleFileSystem};

let data = std::fs::read("Sample.doc")?;
let fs = OleFileSystem::new(OleFile::parse(data)?);

for entry in fs.walk(FPath::new(""), &Default::default()) {
    let entry = entry?;
    println!("{}: {:?} bytes", entry.path, entry.metadata.map(|m| m.size));
}
```

Through a `MountResolver`, so a `.doc` found anywhere in evidence is sniffed and mounted
automatically as a walkable `FileSystem`:

```rust
use forensic_rs::prelude::*;
use frnsc_ole::OleFileSystemFactory;

let resolver = MountResolver::builder()
    .factory(std::sync::Arc::new(OleFileSystemFactory::new()))
    .build();
```

Per-path facts (document author, per-stream allocation/slack, ...), via `PathAttributes` —
reachable without ever naming this crate, from any `dyn FileSystem`:

```rust
if let Some(attrs) = fs.as_attributes() {
    let root_facts = attrs.attributes(FPath::new(""))?;
    println!("{:?}", root_facts.get(&Text::Borrowed("ole.author")));
}
```

## Field naming contract

Every `PathAttributes` key follows `"ole.<scope>.<field>"`, and **a key is omitted, never
zero-filled, when the underlying value is absent** — an absent `ole.author` means the property
set had no author, not an empty string. Booleans are encoded as `Field::U64(0|1)` (`Field` has
no boolean variant).

- The filesystem **root** carries the whole document-level map: format identification
  (`ole.document_type`), property-set metadata (`ole.author`, `ole.title`, `ole.created`, ...),
  encryption state (`ole.encryption`), and container structure (`ole.stream_count`, ...).
- A **storage** path carries its own identity (`ole.storage.path`, `.name`, `.clsid`, `.created`,
  `.modified`, `.child_count`).
- A **stream** path carries its own identity plus allocation facts
  (`ole.stream.size`, `.allocated_size`, `.slack_size`, `.truncated`, `.in_mini_fat`).

## Examples

Run with `cargo run --example <name>`:

- `browse_ole` — mounts a document as an `OleFileSystem` and demonstrates `walk`, `glob`,
  `PathAttributes`, and the name-anomaly report.
- `inspect_ole` — the container-level view: parses a fixture and prints its full directory tree,
  MACB times, and `StructuredObject::attributes()`.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Integration tests under `tests/` follow the fixture-skip pattern: a fixture normally lives at
`artifacts/<name>` (gitignored — never committed, both for size and because a macro-bearing
document risks AV/scanner false positives on the repo itself), and each test prints
`SKIP: fixture '...' unavailable` and returns early when it's not present, rather than failing.

## License

MIT
