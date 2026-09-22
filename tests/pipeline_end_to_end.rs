//! The plan's stated end-to-end acceptance criterion: mount a plain disk-backed VFS, wrap it in
//! `ContainerFs` with `frnsc-ole`'s own factory registered, run `TriagePipeline` with
//! `ContainerInventoryParser` as its only parser, and have an analyzer reach inside the real
//! `.doc` fixture through `ctx.sources().vfs()` -- with zero OLE-specific code anywhere in the
//! pipeline wiring. Follows the same fixture-skip pattern as the rest of this crate's
//! integration tests.

use std::path::Path;
use std::sync::{Arc, Mutex};

use forensic_rs::prelude::*;
use frnsc_ole::OleFileSystemFactory;

const FIXTURE_DIR: &str = "artifacts";
const FIXTURE_NAME: &str = "SampleDoc.doc";

/// A disk-backed VFS rooted at `artifacts/`, so `SampleDoc.doc` is reachable at the plain path
/// "SampleDoc.doc" -- the same shape a triage collection or a mounted image would present. This
/// directory also holds an unrelated `.msi` fixture (itself a CFBF container), which every
/// assertion below must therefore distinguish by path, not just by record shape.
fn disk_vfs() -> Option<Arc<dyn FileSystem>> {
    let path = Path::new(FIXTURE_DIR).join(FIXTURE_NAME);
    if !path.exists() {
        println!("SKIP: fixture '{}' unavailable", path.display());
        return None;
    }
    Some(Arc::new(ChRootFileSystem::new(FIXTURE_DIR, Arc::new(StdVirtualFS::new()))))
}

struct NestedStreamReadingAnalyzer {
    path: String,
    reads: usize,
}

impl Analyzer for NestedStreamReadingAnalyzer {
    fn name(&self) -> &str {
        "nested_stream_reading"
    }
    fn analyze(&mut self, _data: &ForensicData, context: &TriageContext, _out: &mut Vec<Finding>) -> ForensicResult<()> {
        let Some(vfs) = context.sources().vfs() else {
            return Ok(());
        };
        // Reads a stream nested inside the container through the exact same transparent path
        // ContainerInventoryParser's own records name -- no OLE-specific code here at all, just
        // an ordinary FileSystem read.
        if vfs.exists(FPath::new(&self.path)) {
            let bytes = vfs.read_all(FPath::new(&self.path))?;
            assert!(!bytes.is_empty(), "WordDocument stream must not be empty");
            self.reads += 1;
        }
        Ok(())
    }
    fn finalize(&mut self, _context: &TriageContext, _out: &mut Vec<Finding>) -> ForensicResult<()> {
        assert!(self.reads > 0, "the analyzer never reached the nested stream through ctx.sources().vfs()");
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RecordCollector(Arc<Mutex<Vec<ForensicData>>>);

impl TriageSink for RecordCollector {
    fn name(&self) -> &str {
        "record_collector"
    }
    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        self.0.lock().unwrap().push(data.clone());
        Ok(())
    }
    fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
        Ok(())
    }
}

#[test]
fn container_inventory_and_an_analyzer_both_reach_the_real_doc_through_one_transparent_vfs() {
    let Some(disk) = disk_vfs() else { return };

    let resolver = Arc::new(MountResolver::builder().factories(vec![Arc::new(OleFileSystemFactory::new()) as Arc<dyn FormatFactory>]).build());
    // `DescentPolicy::default()` deliberately descends into nothing; `from_resolver` is what a
    // real caller uses to derive the extension allow-list from whatever factories are actually
    // registered (here, frnsc-ole's own CFBF_EXTENSIONS via `OleFileSystemFactory::extensions`).
    let policy = DescentPolicy::from_resolver(&resolver);
    let vfs: Arc<dyn FileSystem> = Arc::new(ContainerFs::new(disk, resolver).with_policy(policy));

    // Sanity check independent of the pipeline: the container's own file still doubles as a
    // directory, and a stream nested one boundary in is an ordinary path.
    assert!(vfs.exists(FPath::new(FIXTURE_NAME)));
    assert!(vfs.exists(FPath::new(&format!("{FIXTURE_NAME}/WordDocument"))));

    let context = TriageContext::new("TEST-HOST", "default");
    let store = context.provenance_store();
    let collector = RecordCollector::default();

    let mut pipeline = TriagePipeline::builder()
        .context(context)
        .parser(Arc::new(ContainerInventoryParser::new()))
        .analyzer(Box::new(NestedStreamReadingAnalyzer {
            path: format!("{FIXTURE_NAME}/WordDocument"),
            reads: 0,
        }))
        .sink(Box::new(collector.clone()))
        .on_parser_error(ErrorAction::Continue)
        .build()
        .unwrap();

    let sources = TriageSources::builder().vfs(vfs).build();
    let result = pipeline.run(&sources).unwrap();

    assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);

    let records = collector.0.lock().unwrap();
    assert!(!records.is_empty(), "ContainerInventoryParser produced no records for a real .doc fixture");

    let mut record_types = std::collections::BTreeSet::new();
    for data in records.iter() {
        let confidence = data.confidence(&store);
        assert_ne!(confidence, Confidence::Unknown, "every record must resolve to a real confidence");
        if let Some(record_type) = data.field_as_str("container.record_type") {
            record_types.insert(record_type.to_string());
        }
    }
    assert!(record_types.len() > 1, "expected more than one container.record_type, got {record_types:?}");
    assert!(record_types.contains(RECORD_TYPE_CONTAINER));
    assert!(record_types.contains(RECORD_TYPE_MEMBER));

    // The container's own record carries the real OLE document facts, forwarded verbatim from
    // frnsc-ole's PathAttributes -- no per-format code anywhere in this test's pipeline wiring.
    let container_record = records
        .iter()
        .find(|d| d.field_as_str("file.path") == Some(FIXTURE_NAME))
        .expect("a container record for SampleDoc.doc");
    assert_eq!(container_record.field_as_str("container.record_type"), Some(RECORD_TYPE_CONTAINER));
    assert_eq!(container_record.field_as_str("ole.document_type"), Some("word_document"));
}
