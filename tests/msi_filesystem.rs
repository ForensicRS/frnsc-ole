//! Integration tests for [`OleFileSystem`] against a real, large (7.5 MB, 58-stream) MSI
//! fixture whose stream names are MSI's own scrambled-Unicode table-name encoding -- the
//! adversarial-looking case the crate's name-sanitization logic must not over-fire on. Follows
//! the same fixture-skip pattern as `tests/msi_fixture.rs`.

use std::path::Path;

use forensic_rs::prelude::*;
use frnsc_ole::{OleFile, OleFileSystem};

const FIXTURE_PATH: &str = "artifacts/microclaudia-setup-x86_64-2.2.3.msi";

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
fn walk_visits_every_stream_and_every_one_round_trips() {
    let Some(fs) = open_fixture() else { return };
    let mut count = 0usize;
    for entry in fs.walk(FPath::new(""), &Default::default()) {
        let entry = entry.unwrap();
        fs.metadata(&entry.path).unwrap_or_else(|e| panic!("metadata('{}') failed: {e}", entry.path));
        if entry.file_type != VFileType::Directory {
            fs.open(&entry.path).unwrap_or_else(|e| panic!("open('{}') failed: {e}", entry.path));
        }
        count += 1;
    }
    assert!(count >= 58, "expected at least 58 entries, walked {count}");
}

#[test]
fn read_dir_count_matches_the_structured_object_view() {
    let Some(fs) = open_fixture() else { return };
    let listed = fs.read_dir(FPath::new("")).unwrap().count();
    assert_eq!(listed, fs.ole().stream_count() + fs.ole().storage_count());
}

/// The negative case that matters most: MSI's own obfuscated table-name encoding must never be
/// mistaken for a `/ \ : !`-containing (or otherwise anomalous) name.
#[test]
fn the_real_fixture_has_no_name_anomalies() {
    let Some(fs) = open_fixture() else { return };
    let anomalies: Vec<_> = fs.name_anomalies().collect();
    assert!(anomalies.is_empty(), "unexpected name anomalies on real scrambled-Unicode MSI names: {anomalies:?}");
}

#[test]
fn root_attributes_identify_it_as_an_installer_package() {
    let Some(fs) = open_fixture() else { return };
    let attrs = fs.as_attributes().unwrap().attributes(FPath::new("")).unwrap();
    assert_eq!(attrs.get(&Text::Borrowed("ole.document_type")), Some(&Field::Text(Text::Borrowed("msi_package"))));
}
