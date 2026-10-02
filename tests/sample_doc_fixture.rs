//! Integration test against `SampleDoc.doc`, a small (27 KB) real legacy Word document from
//! Apache POI's Apache-2.0-licensed `test-data/document/` corpus — the replacement fixture for
//! the oversized MSI in `tests/msi_fixture.rs`. Unlike the MSI test, this fixture's exact stream
//! layout is known (verified once by running the parser against it), so these tests assert
//! specific stream names/sizes rather than just "non-empty".
//!
//! Its streams cover both branches `OleFile::read_stream` chooses between (several are exactly
//! at or above the 4096-byte mini-FAT cutoff, `CompObj` is well under it) and it has a genuinely
//! nested storage (`MsoDataStore/<name>/...`), giving real, non-synthetic coverage `tree.rs`'s
//! storage recursion didn't have before. Follows the same fixture-skip pattern as
//! `msi_fixture.rs`.

use std::path::Path;

use forensic_rs::prelude::*;
use frnsc_ole::{OleFile, OleFormatFactory};

const FIXTURE_PATH: &str = "artifacts/SampleDoc.doc";

fn fixture_bytes() -> Option<Vec<u8>> {
    let path = Path::new(FIXTURE_PATH);
    if !path.exists() {
        println!("SKIP: fixture '{FIXTURE_PATH}' unavailable");
        return None;
    }
    Some(std::fs::read(path).expect("fixture exists but could not be read"))
}

fn open_fixture() -> Option<OleFile> {
    let data = fixture_bytes()?;
    Some(OleFile::parse(data).expect("fixture is a valid CFBF file"))
}

#[test]
fn parses_and_enumerates_all_streams() {
    let Some(ole) = open_fixture() else { return };
    let streams: Vec<&str> = ole.stream_names().collect();
    assert_eq!(streams.len(), 8, "unexpected stream count: {streams:?}");
    // `CompObj`/`SummaryInformation`/`DocumentSummaryInformation` carry a leading 0x01/0x05
    // marker byte per [MS-CFB] 2.6.1 (same as `msi_fixture.rs`), so match on the suffix.
    for expected in [
        "WordDocument",
        "1Table",
        "SummaryInformation",
        "DocumentSummaryInformation",
        "CompObj",
        "Data",
    ] {
        assert!(
            streams.iter().any(|s| s.ends_with(expected)),
            "missing expected stream '{expected}' in {streams:?}"
        );
    }
}

#[test]
fn reads_a_regular_fat_stream() {
    let Some(ole) = open_fixture() else { return };
    // Both are >= the (default 4096-byte) mini-FAT cutoff, so this exercises
    // `ole.rs`'s `fat::read_stream_chain` branch on real, non-synthetic FAT bytes.
    assert_eq!(ole.read_stream("WordDocument").unwrap().len(), 4096);
    assert_eq!(ole.read_stream("1Table").unwrap().len(), 6533);
}

#[test]
fn reads_a_mini_fat_stream() {
    let Some(ole) = open_fixture() else { return };
    // Real name is `"\u{1}CompObj"` (a leading 0x01 marker byte per [MS-CFB] 2.6.1) — match on
    // the suffix rather than hardcoding the marker.
    let name = ole
        .stream_names()
        .find(|s| s.ends_with("CompObj"))
        .expect("fixture has a CompObj stream")
        .to_string();
    // Well under the mini-FAT cutoff: exercises `minifat::read_mini_chain` on real mini-FAT
    // bytes rather than the hand-built ones in `src/minifat.rs`'s unit tests.
    assert_eq!(ole.read_stream(&name).unwrap().len(), 121);
}

#[test]
fn resolves_a_nested_storage_stream() {
    let Some(ole) = open_fixture() else { return };
    // The storage name itself is a real, non-ASCII-looking identifier Word encodes for a GUID —
    // match on prefix/suffix rather than hardcoding it.
    let item_path = ole
        .stream_names()
        .find(|p| p.starts_with("MsoDataStore/") && p.ends_with("/Item"))
        .expect("fixture has a nested MsoDataStore/.../Item stream")
        .to_string();
    let properties_path = ole
        .stream_names()
        .find(|p| p.starts_with("MsoDataStore/") && p.ends_with("/Properties"))
        .expect("fixture has a nested MsoDataStore/.../Properties stream")
        .to_string();

    assert_eq!(ole.read_stream(&item_path).unwrap().len(), 205);
    assert_eq!(ole.read_stream(&properties_path).unwrap().len(), 341);
}

#[test]
fn missing_stream_is_an_error() {
    let Some(ole) = open_fixture() else { return };
    assert!(ole.read_stream("does not exist").is_err());
}

#[test]
fn format_factory_mounts_it_as_a_structured_object() {
    let Some(bytes) = fixture_bytes() else { return };

    let fs: std::sync::Arc<dyn FileSystem> = std::sync::Arc::new(
        forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new().with_file("doc", bytes),
    );
    let mut file = fs.open(FPath::new("doc")).unwrap();
    let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::new()));
    let limits = Limits::default();
    let spill = MemorySpillStore::default();
    let cancellation = forensic_rs::bridge::CancellationToken::default();
    let ctx = MountContext::new(&fs, &locator, &limits, 0, &spill, None, &cancellation);

    let factory = OleFormatFactory::new();
    // A structurally valid header (this fixture's is) now probes as `Exact`, not just `Strong`
    // ("has the magic") -- see `factory.rs`'s `probe_inner`.
    assert_eq!(
        factory.probe(file.as_mut(), &ctx).unwrap(),
        ProbeScore::Exact
    );

    let file = fs.open(FPath::new("doc")).unwrap();
    let mounted = factory.mount(file, &ctx).unwrap();
    let object = mounted
        .as_object()
        .expect("factory declares MountKind::Object");
    // 8 streams + `MsoDataStore` + its one nested GUID-named substorage: storages are now
    // reachable `children()` entries too (as `MountKind::Object`), not just streams.
    let children = object.children().unwrap();
    assert_eq!(children.len(), 10);
    let mso_kind = children
        .iter()
        .find(|(seg, _)| matches!(seg, LocatorSegment::Stream(n) if n.as_str() == "MsoDataStore"))
        .map(|(_, kind)| *kind);
    assert_eq!(mso_kind, Some(MountKind::Object));
}
