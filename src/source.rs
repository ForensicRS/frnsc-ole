//! [`CfbStreams`]: the narrow abstraction every module in the typed document layer (property
//! sets, VBA macros, embedded objects, Word text) reads through instead of depending on
//! [`crate::ole::OleFile`] directly.
//!
//! Two reasons this exists rather than every module just taking `&OleFile`:
//!
//! - **Testability.** Building a real `OleFile` in a unit test means constructing a valid CFBF
//!   byte buffer (header, FAT, directory, sector chains) just to exercise, say, a property-set
//!   decoder that only cares about the bytes of one stream. [`MapStreams`] (test-only) lets
//!   every downstream module's tests hand-build just the stream bytes they need.
//! - **A stable seam.** If `OleFile`'s internals change, only this module's `impl` needs to
//!   change — nothing in `oleps/`, `vba/`, `embedded/`, or `word/` reaches into `OleFile` at all.

use forensic_rs::prelude::*;

use crate::ole::OleFile;

/// Read access to a CFBF container's named streams, by full `"Storage/Stream"` path.
pub trait CfbStreams {
    /// Reads one stream's bytes in full. Errors (rather than returning empty) when no such
    /// stream exists, or when `path` names a storage — callers should not have to guess which
    /// happened from an empty `Vec`.
    fn stream(&self, path: &str) -> ForensicResult<Vec<u8>>;

    /// Whether a *stream* (not a storage) exists at `path`.
    fn has_stream(&self, path: &str) -> bool;
}

impl CfbStreams for OleFile {
    fn stream(&self, path: &str) -> ForensicResult<Vec<u8>> {
        self.read_stream(path)
    }

    fn has_stream(&self, path: &str) -> bool {
        self.entry(path).is_some_and(|e| e.is_stream())
    }
}

/// A hand-built in-memory stream table, for unit-testing the typed document layer without a
/// real CFBF byte buffer. Test-only, never compiled into the published crate.
#[cfg(test)]
pub(crate) struct MapStreams(pub std::collections::BTreeMap<String, Vec<u8>>);

#[cfg(test)]
impl MapStreams {
    pub(crate) fn new() -> Self {
        Self(std::collections::BTreeMap::new())
    }

    pub(crate) fn with(mut self, path: &str, bytes: Vec<u8>) -> Self {
        self.0.insert(path.to_string(), bytes);
        self
    }
}

#[cfg(test)]
impl CfbStreams for MapStreams {
    fn stream(&self, path: &str) -> ForensicResult<Vec<u8>> {
        self.0
            .get(path)
            .cloned()
            .ok_or_else(|| ForensicError::missing_data("ole_stream", CompactString::from(format!("no stream at '{path}'"))))
    }

    fn has_stream(&self, path: &str) -> bool {
        self.0.contains_key(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_streams_round_trips_a_stream() {
        let streams = MapStreams::new().with("A/B", vec![1, 2, 3]);
        assert!(streams.has_stream("A/B"));
        assert_eq!(streams.stream("A/B").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn map_streams_errors_on_a_missing_path() {
        let streams = MapStreams::new();
        assert!(streams.stream("nope").is_err());
        assert!(!streams.has_stream("nope"));
    }
}
