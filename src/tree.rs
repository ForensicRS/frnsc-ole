//! Resolves the directory entries' child/left-sibling/right-sibling links (a red-black tree per
//! storage, per [MS-CFB] 2.6.4) into full `"Storage/Stream"` paths.
//!
//! Walked iteratively with an explicit stack rather than recursively: the directory can hold as
//! many entries as the file is large, and a corrupt or adversarial file could otherwise drive a
//! deep enough sibling chain to overflow the call stack. The same explicit `visited` set that
//! guards recursion depth also catches a cyclic or overlapping (non-tree-shaped) child/sibling
//! graph — a real, well-formed CFBF file never revisits a directory entry, so a revisit is
//! always corruption or an adversarial re-target.

use std::collections::{BTreeMap, HashSet};

use forensic_rs::ensure_format;
use forensic_rs::prelude::*;

use crate::consts::NOSTREAM;
use crate::directory::{DirectoryEntry, ObjectType};

/// Maps every reachable stream's or storage's full path to its index in `entries`. The root
/// storage itself is never a key (it has no name of its own within the container); everything
/// nested under it, streams and storages alike, is. Callers that want streams only should
/// filter by [`DirectoryEntry::is_stream`] (see [`crate::ole::OleFile::stream_names`]).
pub fn build_paths(entries: &[DirectoryEntry]) -> ForensicResult<BTreeMap<String, usize>> {
    let mut paths = BTreeMap::new();
    if entries.is_empty() {
        return Ok(paths);
    }
    ensure_format!(
        matches!(entries[0].object_type, ObjectType::RootStorage),
        "ole_directory",
        "the first directory entry must be the root storage"
    );

    let mut visited = HashSet::new();
    visited.insert(0u32);
    // (node id to visit, path of the storage that owns it)
    let mut stack = vec![(entries[0].child_id, String::new())];

    while let Some((node, parent_path)) = stack.pop() {
        if node == NOSTREAM {
            continue;
        }
        let idx = node as usize;
        if idx >= entries.len() {
            return Err(ForensicError::invalid_format(
                "ole_directory",
                format!("directory entry references out-of-range id {node}"),
            ));
        }
        if !visited.insert(node) {
            return Err(ForensicError::invalid_format(
                "ole_directory",
                format!("directory entry {node} is reachable more than once (cyclic or overlapping tree)"),
            ));
        }

        let entry = &entries[idx];
        let path = if parent_path.is_empty() {
            entry.name.clone()
        } else {
            format!("{parent_path}/{}", entry.name)
        };

        stack.push((entry.left_sibling_id, parent_path.clone()));
        stack.push((entry.right_sibling_id, parent_path));

        match entry.object_type {
            ObjectType::Stream => {
                paths.insert(path, idx);
            }
            ObjectType::Storage => {
                // Storages get a path entry too (so they can be enumerated and opened as
                // zero-length "directory" children), *and* their own children are still
                // walked, keyed under this storage's path as the new parent.
                stack.push((entry.child_id, path.clone()));
                paths.insert(path, idx);
            }
            _ => {}
        }
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, object_type: ObjectType, left: u32, right: u32, child: u32) -> DirectoryEntry {
        DirectoryEntry {
            name: name.to_string(),
            object_type,
            left_sibling_id: left,
            right_sibling_id: right,
            child_id: child,
            clsid: [0; 16],
            start_sector: 0,
            stream_size: 0,
            created: None,
            modified: None,
        }
    }

    #[test]
    fn builds_paths_for_a_stream_nested_in_a_storage() {
        // 0: Root Entry -> child 1
        // 1: "Storage"   -> child 2
        // 2: "Stream"
        let entries = vec![
            entry("Root Entry", ObjectType::RootStorage, NOSTREAM, NOSTREAM, 1),
            entry("Storage", ObjectType::Storage, NOSTREAM, NOSTREAM, 2),
            entry("Stream", ObjectType::Stream, NOSTREAM, NOSTREAM, NOSTREAM),
        ];
        let paths = build_paths(&entries).unwrap();
        assert_eq!(paths.get("Storage/Stream"), Some(&2));
    }

    #[test]
    fn a_storage_gets_its_own_path_entry_as_well_as_its_children() {
        // Same layout as above -- the storage itself must now also be addressable.
        let entries = vec![
            entry("Root Entry", ObjectType::RootStorage, NOSTREAM, NOSTREAM, 1),
            entry("Storage", ObjectType::Storage, NOSTREAM, NOSTREAM, 2),
            entry("Stream", ObjectType::Stream, NOSTREAM, NOSTREAM, NOSTREAM),
        ];
        let paths = build_paths(&entries).unwrap();
        assert_eq!(paths.get("Storage"), Some(&1));
        assert_eq!(paths.get("Storage/Stream"), Some(&2));
    }

    #[test]
    fn a_self_referencing_child_does_not_infinite_loop() {
        let entries = vec![
            entry("Root Entry", ObjectType::RootStorage, NOSTREAM, NOSTREAM, 1),
            entry("Storage", ObjectType::Storage, NOSTREAM, NOSTREAM, 1), // points to itself
        ];
        assert!(build_paths(&entries).is_err());
    }

    #[test]
    fn an_out_of_range_child_id_is_rejected() {
        let entries = vec![entry("Root Entry", ObjectType::RootStorage, NOSTREAM, NOSTREAM, 99)];
        assert!(build_paths(&entries).is_err());
    }

    #[test]
    fn a_sibling_chain_resolves_without_recursing() {
        // Root -> child 1; 1's right sibling is 2, 2's right sibling is 3, ... a long chain.
        let mut entries = vec![entry("Root Entry", ObjectType::RootStorage, NOSTREAM, NOSTREAM, 1)];
        let count = 10_000;
        for i in 0..count {
            let right = if i + 1 < count { (i + 2) as u32 } else { NOSTREAM };
            entries.push(entry(&format!("s{i}"), ObjectType::Stream, NOSTREAM, right, NOSTREAM));
        }
        let paths = build_paths(&entries).unwrap();
        assert_eq!(paths.len(), count);
    }
}
