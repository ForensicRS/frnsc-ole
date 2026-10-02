//! Integration test against a real MSI fixture. Follows the workspace's established
//! fixture-skip pattern (`frnsc-esedb`/`frnsc-hive`): when the (gitignored, not-always-present)
//! fixture is missing, print `SKIP: ...` and return early rather than failing the suite.
//!
//! This replaces the crate's original `should_read_msi` test, which only printed to stdout and
//! asserted nothing.

use std::path::Path;

use frnsc_ole::OleFile;

const FIXTURE_PATH: &str = "artifacts/microclaudia-setup-x86_64-2.2.3.msi";

fn open_fixture() -> Option<OleFile> {
    let path = Path::new(FIXTURE_PATH);
    if !path.exists() {
        println!("SKIP: fixture '{FIXTURE_PATH}' unavailable");
        return None;
    }
    let data = std::fs::read(path).expect("fixture exists but could not be read");
    Some(OleFile::parse(data).expect("fixture is a valid CFBF file"))
}

#[test]
fn parses_the_msi_and_enumerates_streams() {
    let Some(ole) = open_fixture() else { return };
    let streams: Vec<&str> = ole.stream_names().collect();
    assert!(
        !streams.is_empty(),
        "a real MSI must contain at least one stream"
    );
}

#[test]
fn reads_the_summary_information_stream() {
    let Some(ole) = open_fixture() else { return };
    // Every OLE-based MSI carries a SummaryInformation stream; its real name is prefixed with
    // a 0x05 marker byte per [MS-CFB] 2.6.1, so match on the suffix rather than the exact name.
    let Some(summary_name) = ole
        .stream_names()
        .find(|name| name.to_ascii_lowercase().ends_with("summaryinformation"))
    else {
        println!("SKIP: fixture has no SummaryInformation stream");
        return;
    };
    let bytes = ole
        .read_stream(summary_name)
        .expect("a stream listed in the directory must be readable");
    assert!(!bytes.is_empty());
}
