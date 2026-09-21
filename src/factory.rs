//! `forensic_rs::traits::format::FormatFactory` implementation — sniffs and mounts a CFBF file
//! as a [`Mounted::Object`], structured like `frnsc-hive`'s `HiveFormatFactory` (probe restores
//! the stream position on every path including an error return; mount hands back an
//! `Arc`-wrapped reader), plus the two `EseFormatFactory`-style hardenings `frnsc-esedb` already
//! applies: a `Limits::materialize_in_memory_limit` check before reading, and `.with_path(..)`
//! on every parse error.

use std::io::{Read, SeekFrom};
use std::sync::Arc;

use forensic_rs::prelude::*;

use crate::consts::OLE_SIGNATURE;
use crate::header::Header;
use crate::ole::OleFile;

#[derive(Debug, Default, Clone, Copy)]
pub struct OleFormatFactory;

impl OleFormatFactory {
    pub fn new() -> Self {
        Self
    }
}

impl FormatFactory for OleFormatFactory {
    fn name(&self) -> &'static str {
        "frnsc-ole"
    }

    fn yields(&self) -> MountKind {
        MountKind::Object
    }

    /// Checks the 8-byte CFBF magic, and — if a full 512-byte header is available — whether it
    /// is structurally valid ([`Header::parse`] already validates byte order, sector shift, and
    /// the major-version/sector-size cross-check). Per [`FormatFactory::probe`]'s contract,
    /// restores the stream position before returning on every path, including an error return.
    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let initial_pos = file.stream_position().unwrap_or(0);
        let result = probe_inner(file);
        file.seek(SeekFrom::Start(initial_pos))
            .map_err(|e| ForensicError::io_error_with_source(e, "restoring stream position after probing"))?;
        result
    }

    /// Reads the whole file (bounded by [`Limits::materialize_in_memory_limit`]) and parses it
    /// into an [`OleFile`], wrapped as `Mounted::Object`.
    ///
    /// Refuses rather than spilling when the file is too large: `OleFile` is `data: Vec<u8>` by
    /// construction, with every sector chain resolved by slicing that buffer, and a
    /// [`MemorySpillStore`](forensic_rs::core::limits::MemorySpillStore)-backed
    /// [`VirtualFile`] cannot feed `OleFile::parse`'s `Vec<u8>` without being read back into
    /// memory in full first — which would defeat the budget it's supposedly enforcing. An
    /// honest refusal, naming the observed size and the limit, is the correct answer until
    /// `OleFile` itself grows a streaming mode.
    fn mount(&self, mut file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let limit = ctx.limits().materialize_in_memory_limit as u64;

        // Cheap early-out when the backend can report size without reading. Not authoritative
        // on its own -- a backend may report 0 or a stale value -- so the `take` below is what
        // actually enforces the budget.
        if let Ok(meta) = file.metadata() {
            if meta.size > limit {
                return Err(too_large(meta.size, limit).with_path(ctx.locator().to_string()));
            }
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|e| ForensicError::io_error_with_source(e, "seeking to start before mounting"))?;
        let mut data = Vec::new();
        // Read at most `limit + 1` bytes: enough to prove "over the limit" without ever
        // allocating past it, and without trusting the (possibly wrong) reported size for
        // anything but the cheap early-out above.
        Read::take(&mut *file, limit + 1)
            .read_to_end(&mut data)
            .map_err(|e| ForensicError::io_error_with_source(e, "reading OLE container into memory"))?;
        if data.len() as u64 > limit {
            return Err(too_large(data.len() as u64, limit).with_path(ctx.locator().to_string()));
        }

        let ole = OleFile::parse(data).map_err(|e| e.with_path(ctx.locator().to_string()))?;
        Ok(Mounted::Object(Arc::new(ole)))
    }
}

fn too_large(observed: u64, limit: u64) -> ForensicError {
    ForensicError::other(
        "frnsc-ole",
        format!("CFBF container is {observed} bytes, exceeding the {limit}-byte in-memory materialization limit"),
    )
}

fn probe_inner(file: &mut dyn VirtualFile) -> ForensicResult<ProbeScore> {
    let mut head = [0u8; crate::consts::HEADER_SIZE];
    if file.read_exact(&mut head).is_err() {
        // A short/truncated file is simply "not this format", not a probe failure.
        return Ok(ProbeScore::No);
    }
    if head[..8] != OLE_SIGNATURE {
        return Ok(ProbeScore::No);
    }
    // Magic alone can collide; a header that also passes full structural validation
    // (byte order, sector shift, mini-sector shift, the v3/512 cross-check) is unambiguous.
    Ok(if Header::parse(&head).is_ok() { ProbeScore::Exact } else { ProbeScore::Strong })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc as StdArc;

    use forensic_rs::core::limits::{Limits, MemorySpillStore};
    use forensic_rs::core::locator::{EvidenceLocator, LocatorSegment};
    use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;

    use super::*;

    fn probe_ctx<'a>(
        fs: &'a Arc<dyn FileSystem>,
        locator: &'a EvidenceLocator,
        limits: &'a Limits,
        spill: &'a MemorySpillStore,
        cancellation: &'a forensic_rs::bridge::CancellationToken,
    ) -> MountContext<'a> {
        MountContext::new(fs, locator, limits, 0, spill, None, cancellation)
    }

    fn valid_header_bytes() -> Vec<u8> {
        // Mirrors header.rs's own `valid_header_bytes` fixture -- a structurally valid v3/512
        // header with no directory/mini-FAT/DIFAT chains.
        let mut buf = vec![0u8; crate::consts::HEADER_SIZE];
        buf[0..8].copy_from_slice(&OLE_SIGNATURE);
        buf[26..28].copy_from_slice(&3u16.to_le_bytes());
        buf[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        buf[30..32].copy_from_slice(&0x0009u16.to_le_bytes());
        buf[32..34].copy_from_slice(&0x0006u16.to_le_bytes());
        buf[48..52].copy_from_slice(&crate::consts::ENDOFCHAIN.to_le_bytes());
        buf[56..60].copy_from_slice(&4096u32.to_le_bytes());
        buf[60..64].copy_from_slice(&crate::consts::ENDOFCHAIN.to_le_bytes());
        buf[68..72].copy_from_slice(&crate::consts::ENDOFCHAIN.to_le_bytes());
        for slot in buf[76..76 + crate::consts::HEADER_DIFAT_ENTRIES * 4].chunks_exact_mut(4) {
            slot.copy_from_slice(&crate::consts::FREESECT.to_le_bytes());
        }
        buf
    }

    #[test]
    fn probe_scores_no_on_a_non_ole_file() {
        let fs: Arc<dyn FileSystem> =
            StdArc::new(InMemoryVirtualFileSystem::new().with_file("not_ole", b"just some bytes".to_vec()));
        let mut file = fs.open(FPath::new("not_ole")).unwrap();
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::new()));
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let ctx = probe_ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = OleFormatFactory::new();
        let pos_before = file.stream_position().unwrap();
        let score = factory.probe(file.as_mut(), &ctx).unwrap();
        assert_eq!(ProbeScore::No, score);
        assert_eq!(pos_before, file.stream_position().unwrap(), "probe must restore stream position");
    }

    #[test]
    fn probe_scores_strong_on_the_magic_alone() {
        let mut bytes = OLE_SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0u8; 504]); // pad to a full header of garbage past the magic
        let fs: Arc<dyn FileSystem> = StdArc::new(InMemoryVirtualFileSystem::new().with_file("ole_file", bytes));
        let mut file = fs.open(FPath::new("ole_file")).unwrap();
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::new()));
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let ctx = probe_ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = OleFormatFactory::new();
        let score = factory.probe(file.as_mut(), &ctx).unwrap();
        assert_eq!(ProbeScore::Strong, score);
    }

    #[test]
    fn probe_scores_exact_on_a_structurally_valid_header() {
        let fs: Arc<dyn FileSystem> =
            StdArc::new(InMemoryVirtualFileSystem::new().with_file("ole_file", valid_header_bytes()));
        let mut file = fs.open(FPath::new("ole_file")).unwrap();
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::new()));
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let ctx = probe_ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = OleFormatFactory::new();
        let pos_before = file.stream_position().unwrap();
        let score = factory.probe(file.as_mut(), &ctx).unwrap();
        assert_eq!(ProbeScore::Exact, score);
        assert_eq!(pos_before, file.stream_position().unwrap(), "probe must restore stream position");
    }

    #[test]
    fn mount_yields_a_structured_object_with_no_streams_for_a_minimal_file() {
        let bytes = crate::ole::tests_support::minimal_ole_bytes();
        let fs: Arc<dyn FileSystem> = StdArc::new(InMemoryVirtualFileSystem::new().with_file("ole_file", bytes));
        let file = fs.open(FPath::new("ole_file")).unwrap();
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::new()));
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let ctx = probe_ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = OleFormatFactory::new();
        let mounted = factory.mount(file, &ctx).unwrap();
        let object = mounted.as_object().expect("factory declares MountKind::Object");
        assert!(object.children().unwrap().is_empty());
    }

    #[test]
    fn mount_refuses_a_file_larger_than_the_memory_limit() {
        let bytes = crate::ole::tests_support::minimal_ole_bytes();
        let fs: Arc<dyn FileSystem> = StdArc::new(InMemoryVirtualFileSystem::new().with_file("ole_file", bytes));
        let file = fs.open(FPath::new("ole_file")).unwrap();
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("ole_file")));
        let limits = Limits { materialize_in_memory_limit: 16, ..Limits::default() };
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let ctx = probe_ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = OleFormatFactory::new();
        let message = match factory.mount(file, &ctx) {
            Ok(_) => panic!("expected mount to refuse an oversized file"),
            Err(e) => e.to_string(),
        };
        assert!(message.contains("16"), "error should name the limit: {message}");
    }
}
