# frnsc-ole Agent Guide

## Project Overview

`frnsc-ole` parses the MS-CFB container layer (header, DIFAT/FAT, mini-FAT, directory tree) and,
on top of that, a typed document view (property sets, VBA macros, embedded objects, Word text)
not bound to any framework trait. The container reaches the rest of the ecosystem primarily as
**`OleFileSystem: forensic_rs::FileSystem`** (storages are directories, streams are files) plus
`forensic_rs::traits::vfs::PathAttributes` for per-path facts — so every generic VFS-based tool
(`walk`, `glob`, the bridge's `VfsProvider`, MCP resource browsing, `AuthorizedVirtualFileSystem`
policy enforcement) works over a document's internals with **zero OLE-specific code anywhere
downstream**. `OleFile`'s `StructuredObject` implementation is kept for the embedding
relationship (an OLE document embedded inside another format) but is not the primary surface.

Why `FileSystem` and not a bespoke pipeline/bridge/MCP integration: see
`forensic-rs/AGENTS.md`'s "Capability probes are how optional power is discovered" — an inherent
method (what this crate used to expose document facts through) is invisible to any caller
holding `dyn FileSystem`, which is every generic triage tool; a capability probe is not.

**Depends on:** [`forensic-rs`](https://github.com/ForensicRS/forensic-rs) 0.14

## Review discipline

Apply the `forensic-rs-tool-review` skill (copied into `.claude/skills/`) to every change here:
it covers the trait-layering contract, forensic soundness (never fabricate a missing timestamp,
source divergence is evidence not noise, the Finding/log/error three-way split), and
adversarial-input robustness (no panics on evidence bytes, bounds-checked parsing). Don't restate
that content here — this file is for what's specific to `frnsc-ole`.

## Rules specific to this crate

- **A zero FILETIME in a directory entry means unset, not 1601-01-01.** [MS-CFB] 2.6.1 mandates
  zero for stream objects, and most writers also leave storages at zero. Never map a zero
  FILETIME through `ForensicTimestamp::from_win_filetime` — `filetime_or_none` in `directory.rs`
  is the one place this conversion happens; route through it, don't reimplement it.
- **`ole.*` keys are omitted, never zero-filled, when the value is absent** — in `attributes()`,
  in every `ForensicData` field, in `BridgeValue` (→ omit the key or use `BridgeValue::Null`,
  per what the call site needs), and in `CapabilityValue` (omit the key entirely —
  `ValueType::Timestamp` does not match `CapabilityValue::Null`, so a nulled timestamp fails
  output-schema validation instead of just looking odd).
- **This crate ships no `Analyzer` and no scoring.** Fields like a future
  `macro_stomping_suspected` name an *observation* (e.g. `_VBA_PROJECT` performance-cache
  disagreeing with the compressed source), never a verdict. If you find yourself adding a
  severity or a risk score, it belongs in a downstream crate, not here.
- **`OleFile` holds the whole file in memory.** Every entry point that materializes bytes must
  bound the read against `Limits::materialize_in_memory_limit` *before* allocating (see
  `factory.rs::mount`, which uses a `Read::take(limit + 1)` cap rather than trusting a
  backend-reported size). Do not "fix" `mount` to use `ctx.spill()` on an oversized file — a
  spilled `VirtualFile` cannot feed `OleFile::parse(Vec<u8>)` without being read back into memory
  in full, which defeats the budget it's supposedly enforcing. Refusing with an error naming the
  observed size and the limit is the correct behavior until `OleFile` grows a genuine streaming
  mode.
- **The directory tree is attacker-controlled input.** `tree.rs`'s `visited` set and its
  explicit-stack (non-recursive) walk are load-bearing against a corrupt or adversarial
  child/sibling graph — never replace the stack with recursion, and never relax the
  out-of-range-id or already-visited checks.
- **A bridge hook holds no parsed state.** Every `ProviderHook` call re-derives from the
  underlying bytes; caching a fully-parsed document per hook instance would mean retaining it in
  memory for the hook's whole lifetime.
- **A per-document parse failure during pipeline discovery is a `ParseFailure` record, not a
  propagated `Err`.** One corrupt or encrypted file must never abort a whole-disk walk under the
  pipeline's default `ErrorAction::Continue`/`Halt` semantics, and "this had the CFBF magic and
  would not parse" is itself forensically meaningful evidence, not a diagnostic to discard.
- **Zero serde.** Serialization is delegated entirely to `forensic-rs`'s own `ForensicData` /
  `BridgeValue` / `CapabilityValue`, matching every sibling crate in this ecosystem.
- **No bins.** `examples/` is this ecosystem's substitute for a CLI.
- **`FileSystem::metadata()` must never materialize a stream's bytes.** It is called once per
  entry during a directory walk; use `OleFile::stream_allocation`/`chain::count_chain` (walks
  the FAT/mini-FAT chain to get its *length* only) rather than `read_stream`/`follow_chain`,
  which must read every sector.
- **`children_of()` is O(total paths) per call — never use it in a loop.** Use
  `OleFile::children_iter()` (a lazy `BTreeMap::range` scan) for anything that visits more than
  one storage's children, or a walk becomes O(n²) on an attacker-controlled directory tree.
- **A directory-entry name is skipped and reported, never silently rejected-whole-mount or
  escaped.** [MS-CFB] 2.6.1 forbids `/ \ : !`; `FPath` treats `/`/`\` as separators and `X:` as
  a drive, so such a name is both a spec violation and a path-confusion vector. The policy is
  `crate::names::classify` + `OleFileSystem::hidden` — exclude the entry from the `FileSystem`
  surface, keep it visible via `OleFile::entries()` and `OleFileSystem::name_anomalies()`. Do
  not widen the character set beyond exactly those four plus `.`/`..`/empty: over-filtering
  (flagging an unusual-but-legal name — a `\x01`/`\x05` marker byte, MSI's obfuscated Unicode
  table names) silently hides real evidence, which is the actual risk here. Any change to
  `classify` must re-run against the MSI fixture and assert `name_anomalies().is_empty()` still
  holds.
- **`OleFileSystem::case_sensitivity()` is `Insensitive` because [MS-CFB] 2.6.4 says so**
  (siblings are ordered by uppercase-mapped name), not as a convenience default. Lookup is
  exact-match-first, then a precomputed case-fold index; an ambiguous fold (two addressable
  entries folding to the same key — itself a spec violation) refuses rather than guessing, while
  both entries stay reachable by their own exact names.
- **`OleFileSystem::new`/`from_arc` must never touch `OleFile::document()`.** A caller that only
  walks and reads streams must not pay for property-set/format decoding it never asked for —
  that's the entire reason `document()` is `OnceLock`-cached instead of eager.
- **A zero-declared-size stream's `start_sector` cannot be trusted.** [MS-CFB] 2.6.1 mandates
  `NOSTREAM`/`ENDOFCHAIN` there, but a non-compliant writer (or a hand-built test fixture) can
  leave it at something else. `read_stream_by_index`/`stream_allocation_by_index` both
  short-circuit on declared size == 0 before attempting any chain walk; don't remove that guard
  to "simplify" the code.

## Module structure

```
src/
├── consts.rs      -- [MS-CFB] constants (signature, sector markers, sizes)
├── header.rs       -- 512-byte CFBF header
├── fat.rs           -- DIFAT + FAT, regular sector reads
├── chain.rs          -- generic cycle-safe FAT/mini-FAT chain walker (+ count-only variant)
├── minifat.rs         -- mini-FAT + mini stream
├── directory.rs        -- 128-byte directory entry records, incl. MACB times
├── tree.rs               -- child/sibling red-black tree -> "Storage/Stream" paths
├── guid.rs                -- canonical mixed-endian CLSID/GUID formatting
├── names.rs                -- NameAnomaly + classify: what can't be an FPath component
├── ole.rs                   -- OleFile: StructuredObject impl, container-level public API
├── filesystem.rs              -- OleFileSystem: FileSystem + PathAttributes impl (primary surface)
└── factory.rs                  -- OleFormatFactory/OleFileSystemFactory: FormatFactory impls
```

Later phases add the rest of the typed document layer (VBA, embedded objects, Word text), which
feeds `PathAttributes` as additional `ole.*` keys with no structural change to the above.

## Error handling

`ForensicResult<T>` / `ForensicError` throughout, no crate-local error enum. A magic/signature
mismatch is a hard `ForensicError` (this isn't the claimed format at all). A structural
inconsistency that is still forensically meaningful (e.g. a stream's declared size disagreeing
with its allocated chain length) is recorded as a fact on the parsed type, not rejected.

## Testing

Unit tests are inline `#[cfg(test)] mod tests` per module, with hand-built byte fixtures.
Integration tests under `tests/` use the fixture-skip pattern (`println!("SKIP: fixture '...'
unavailable")` + early return) — see `README.md`'s Development section. Beyond the
`forensic-rs-tool-review` skill's testing guidance: when adding an assertion against a real
fixture's bytes, run the parser against it first and assert the answer you actually observed,
never one you assumed the fixture would contain.
