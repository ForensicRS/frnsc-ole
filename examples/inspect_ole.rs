//! Parses a CFBF file and prints its directory tree (streams and storages, with MACB times,
//! declared/allocated size, and CLSID), followed by the container-level `attributes()` summary.
//! The house substitute for a CLI in this ecosystem — see `README.md`'s Development section.
//!
//! Run with: cargo run --example inspect_ole -- <path-to-a-.doc-or-.msi-or-other-CFBF-file>
//!
//! With no argument, falls back to `artifacts/SampleDoc.doc` if present.

use forensic_rs::traits::format::StructuredObject;
use frnsc_ole::{ObjectType, OleFile};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "artifacts/SampleDoc.doc".to_string());
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("could not read '{path}': {e}");
            eprintln!("usage: cargo run --example inspect_ole -- <path-to-CFBF-file>");
            std::process::exit(1);
        }
    };

    let ole = match OleFile::parse(data) {
        Ok(ole) => ole,
        Err(e) => {
            eprintln!("'{path}' is not a valid CFBF file: {e}");
            std::process::exit(1);
        }
    };

    println!("== {path} ==\n");

    println!(
        "root CLSID: {}",
        ole.root_clsid().unwrap_or_else(|| "(none)".to_string())
    );
    println!("streams: {}, storages: {}\n", ole.stream_count(), ole.storage_count());

    println!("-- directory tree --");
    for (path, kind) in ole.paths() {
        let depth = path.matches('/').count();
        let indent = "  ".repeat(depth);
        let leaf = path.rsplit('/').next().unwrap_or(path);
        match kind {
            ObjectType::Stream => {
                let entry = ole.entry(path).expect("path came from ole.paths()");
                let created = entry.created.map(|t| format!("{t:?}")).unwrap_or_else(|| "-".into());
                let modified = entry.modified.map(|t| format!("{t:?}")).unwrap_or_else(|| "-".into());
                println!(
                    "{indent}{leaf}  [{} bytes, created={created}, modified={modified}]",
                    entry.stream_size
                );
            }
            _ => println!("{indent}{leaf}/"),
        }
    }

    let unallocated: Vec<_> = ole.unallocated_entries().collect();
    if !unallocated.is_empty() {
        println!("\n-- unallocated (deleted) directory slots --");
        for (idx, entry) in unallocated {
            println!("  [{idx}] {:?} name={:?} size={}", entry.object_type, entry.name, entry.stream_size);
        }
    }

    println!("\n-- attributes() --");
    for (key, value) in ole.attributes() {
        println!("  {key} = {value:?}");
    }
}
