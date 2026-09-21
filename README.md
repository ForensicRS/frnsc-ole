# frnsc-ole

[![crates.io](https://img.shields.io/crates/v/frnsc-ole.svg)](https://crates.io/crates/frnsc-ole)
[![docs.rs](https://docs.rs/frnsc-ole/badge.svg)](https://docs.rs/frnsc-ole)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/ForensicRS/frnsc-ole/actions/workflows/rust.yml/badge.svg)](https://github.com/ForensicRS/frnsc-ole/actions/workflows/rust.yml)

Reads OLE Compound File Binary Format (CFBF) containers — `.msi`, legacy Office documents
(`.doc`/`.xls`/`.ppt`), Outlook `.msg`, Visio/Publisher files, and other structured-storage
formats — and, on top of the container, extracts document metadata, VBA macro source, embedded
objects, and (for legacy Word documents) plain text.

**Implements:** `StructuredObject` + `FormatFactory` (`Mounted::Object`) for the CFBF container
layer, and `ArtifactParserFactory` + a bridge `ProviderHook` so the typed document contents reach
a `TriagePipeline` run or an interactive evidence browser without a caller writing that plumbing
by hand. Behind the optional `capabilities` feature, it also ships a set of `ForensicTool`s for
direct MCP-style invocation.

Built on [`forensic-rs`](https://github.com/ForensicRS/forensic-rs), which decouples forensic
analysis logic from data access: code written against this crate's trait implementations reads
the same `.doc` whether it came from a live path, a raw disk image, a triage collection, a nested
ZIP a `MountResolver` already unpacked, or an `InMemoryVirtualFileSystem` in a test — this crate
is never named in that analysis code.

## Status & limitations

- The whole container is held in memory (`OleFile::parse(Vec<u8>)`); CFBF containers in forensic
  practice are file-sized, not volume-sized, so this trades a bounded amount of memory for never
  re-seeking the original source while resolving sector chains. `OleFormatFactory::mount` refuses
  (rather than silently truncating) a file larger than
  `Limits::materialize_in_memory_limit`, and does **not** fall back to a spilled/streaming
  reader — see `AGENTS.md` for why that would defeat the budget it's enforcing.
- Only little-endian MS-CFB v3 (512-byte sectors) and v4 (4096-byte sectors) are supported, with
  64-byte mini sectors — the combination every real-world writer produces.
- Read-only. This crate never writes to evidence.
- **Facts only, no scoring.** This crate extracts primitives — macro source, embedded files,
  property values, document text, and stomping *evidence* — and deliberately ships no malware
  detection, keyword matching, or verdicts. Build that downstream, on top of what this crate
  surfaces.

## Usage

Directly, from bytes you already have:

```rust
use frnsc_ole::OleFile;

let data = std::fs::read("Sample.doc")?;
let ole = OleFile::parse(data)?;
for name in ole.stream_names() {
    println!("{name}: {} bytes", ole.read_stream(name)?.len());
}
```

Through a `MountResolver`, so a `.doc` found anywhere in evidence is sniffed and opened
automatically:

```rust
use forensic_rs::prelude::*;
use frnsc_ole::OleFormatFactory;

let resolver = MountResolver::builder()
    .factory(std::sync::Arc::new(OleFormatFactory::new()))
    .build();
```

Through a `TriagePipeline`, so every OLE document anywhere under a VFS root is discovered and
emitted as records:

```rust
use forensic_rs::prelude::*;
use frnsc_ole::OleParserFactory;

let pipeline = TriagePipeline::builder()
    .context(context)
    .parser(std::sync::Arc::new(OleParserFactory::new()))
    .sink(Box::new(sink))
    .build()?;
```

## Pipeline integration

`OleParserFactory` (`ArtifactParserFactory`, descriptor id `"document.ole"`) walks a configured
`FileSystem` looking for OLE documents (by extension, by content-sniffing the 8-byte CFBF magic,
or both — see `DiscoveryMode` below) and emits one or more `ForensicData` records per document.

**Field naming contract**, followed by every record this crate emits:

- Every field key is `"ole.<record>.<field>"`.
- Every record carries a shared `ole.record_type` discriminator and a shared `ole.document.path`
  (the document's VFS path — the join key across a document's records).
- Every record carries a shared `ole.timestamp`, so one `TimelineSink`/`JsonlTimelineSink` works
  uniformly over this parser's whole output, regardless of record type.
- **A key is omitted, never zero-filled, when the underlying value is absent.** An absent
  `ole.document.author` means the property set had no author, not an empty string. Booleans are
  encoded as `Field::U64(0|1)` (`Field` has no boolean variant).
- Record types: `Document` (one per discovered file), `Stream` (one per directory entry),
  `VbaModule` (one per macro module), `EmbeddedObject` (one per embedded object), `ParseFailure`
  (a document that looked like CFBF and would not parse — this is a *record*, not a pipeline
  error, so one bad file never aborts a whole-disk run).

**`DiscoveryMode`** trades cost for coverage: `ByExtension` (default) only opens files whose name
matches a known OLE-bearing extension; `ByContent` magic-sniffs every file in the configured size
band, which is what catches a *renamed* document (a real adversarial case) but costs one `open()`
per candidate file on a whole disk image. Choose deliberately via `DiscoveryConfig`.

## Bridge integration

`OleHook` (`ProviderHook`) matches any file whose content starts with the CFBF magic and exposes
a virtual `[ole]` namespace under it: `metadata`, `streams`, `macros`, `embedded`, `text`, each
paginated. It holds no parsed state between calls — every read re-derives from the underlying
bytes — so it is safe to attach to a `VfsProvider` over an entire evidence tree.

## MCP capability integration (`--features capabilities`)

Six read-only `ForensicTool`s: `ole.inspect`, `ole.list_streams`, `ole.read_stream`,
`ole.extract_macros`, `ole.extract_text`, `ole.extract_embedded`. Every invocation is
authorized per-call against the caller's `AccessContext`; a denied path returns
`CapabilityError::not_found()`, never `AccessDenied` — indistinguishable from a genuinely
missing path, matching the framework's own capability-hiding rule.

## Examples

Run any of these with `cargo run --example <name>` (`mcp_ole_tools` additionally needs
`--features capabilities`):

- `inspect_ole` — parses a fixture and prints its full directory tree, MACB times, and
  document metadata.
- `pipeline_ole` — runs `OleParserFactory` through a real `TriagePipeline`.
- `bridge_ole` — browses a document through `OleHook` via a `BridgeClient`.
- `mcp_ole_tools` — registers and invokes the `ForensicTool`s directly.

## Development

```sh
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

Integration tests under `tests/` follow the fixture-skip pattern: a fixture normally lives at
`artifacts/<name>` (gitignored — never committed, both for size and because a macro-bearing
document risks AV/scanner false positives on the repo itself), and each test prints
`SKIP: fixture '...' unavailable` and returns early when it's not present, rather than failing.

## License

MIT
