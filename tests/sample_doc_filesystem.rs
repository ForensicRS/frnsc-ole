//! Integration tests for [`OleFileSystem`] against `SampleDoc.doc` -- the same 8-stream,
//! 2-nested-storage fixture `tests/sample_doc_fixture.rs` already exercises through
//! `StructuredObject`, here exercised through the `FileSystem` surface instead. Follows the
//! same fixture-skip pattern.

use std::path::Path;

use forensic_rs::prelude::*;
use frnsc_ole::{OleFile, OleFileSystem};

const FIXTURE_PATH: &str = "artifacts/SampleDoc.doc";

fn open_fixture() -> Option<OleFileSystem> {
    let path = Path::new(FIXTURE_PATH);
    if !path.exists() {
        println!("SKIP: fixture '{FIXTURE_PATH}' unavailable");
        return None;
    }
    let data = std::fs::read(path).expect("fixture exists but could not be read");
    let ole = OleFile::parse(data).expect("fixture is a valid CFBF file");
    Some(OleFileSystem::new(ole))
}

#[test]
fn root_lists_six_streams_and_one_nested_storage() {
    let Some(fs) = open_fixture() else { return };
    // 8 streams total (per sample_doc_fixture.rs), 2 of them nested inside MsoDataStore -- so
    // the root listing is the other 6 streams plus the MsoDataStore storage itself.
    let root: Vec<String> = fs
        .read_dir(FPath::new(""))
        .unwrap()
        .map(|e| e.unwrap().path.to_string())
        .collect();
    assert_eq!(root.len(), 7, "unexpected root listing: {root:?}");
    assert!(root.iter().any(|p| p == "MsoDataStore"));
}

#[test]
fn walk_visits_every_stream_and_storage_exactly_once() {
    let Some(fs) = open_fixture() else { return };
    // 8 streams + MsoDataStore + its one nested GUID-named substorage = 10, matching
    // sample_doc_fixture.rs's `children().len() == 10` assertion for the same fixture.
    let entries: Vec<DirEntry> = fs
        .walk(FPath::new(""), &Default::default())
        .map(|e| e.unwrap())
        .collect();
    assert_eq!(entries.len(), 10, "unexpected walk: {entries:?}");
}

#[test]
fn every_walked_entry_round_trips_through_open_and_metadata() {
    let Some(fs) = open_fixture() else { return };
    for entry in fs.walk(FPath::new(""), &Default::default()) {
        let entry = entry.unwrap();
        let meta = fs
            .metadata(&entry.path)
            .unwrap_or_else(|e| panic!("metadata('{}') failed: {e}", entry.path));
        assert_eq!(meta.file_type, entry.file_type);
        if entry.file_type != VFileType::Directory {
            fs.open(&entry.path)
                .unwrap_or_else(|e| panic!("open('{}') failed: {e}", entry.path));
        }
    }
}

#[test]
fn reads_the_same_bytes_as_the_structured_object_view() {
    let Some(fs) = open_fixture() else { return };
    assert_eq!(fs.read_all(FPath::new("WordDocument")).unwrap().len(), 4096);
    assert_eq!(fs.read_all(FPath::new("1Table")).unwrap().len(), 6533);
}

#[test]
fn glob_reaches_a_stream_nested_inside_a_scrambled_unicode_storage_name() {
    let Some(fs) = open_fixture() else { return };
    let matches = fs.glob("MsoDataStore/*/Item").unwrap();
    assert_eq!(matches.len(), 1, "unexpected glob matches: {matches:?}");
}

#[test]
fn case_insensitive_lookup_resolves_a_real_stream() {
    let Some(fs) = open_fixture() else { return };
    assert!(fs.metadata(FPath::new("worddocument")).is_ok());
    assert!(fs.metadata(FPath::new("WORDDOCUMENT")).is_ok());
}

#[test]
fn root_attributes_report_document_metadata() {
    let Some(fs) = open_fixture() else { return };
    let attrs = fs
        .as_attributes()
        .unwrap()
        .attributes(FPath::new(""))
        .unwrap();
    assert_eq!(
        attrs.get(&Text::Borrowed("ole.document_type")),
        Some(&Field::Text(Text::Borrowed("word_document")))
    );
    match attrs.get(&Text::Borrowed("ole.author")) {
        Some(Field::Text(t)) => assert_eq!(t.as_ref(), "Nick Burch"),
        other => panic!("expected the real author, got {other:?}"),
    }
}

#[test]
fn stream_attributes_report_slack() {
    let Some(fs) = open_fixture() else { return };
    // 1Table is 6533 declared bytes over a 512-byte sector size -> 6656 allocated, 123 slack.
    let attrs = fs
        .as_attributes()
        .unwrap()
        .attributes(FPath::new("1Table"))
        .unwrap();
    assert_eq!(
        attrs.get(&Text::Borrowed("ole.stream.allocated_size")),
        Some(&Field::U64(6656))
    );
    assert_eq!(
        attrs.get(&Text::Borrowed("ole.stream.slack_size")),
        Some(&Field::U64(123))
    );
}

#[test]
fn the_real_fixture_has_no_name_anomalies() {
    let Some(fs) = open_fixture() else { return };
    let anomalies: Vec<_> = fs.name_anomalies().collect();
    assert!(
        anomalies.is_empty(),
        "unexpected name anomalies on real data: {anomalies:?}"
    );
}
