//! Browses an OLE/CFBF document as an ordinary `forensic_rs::FileSystem` -- the crate's primary
//! integration surface, alongside `OleFormatFactory`/`OleFileSystemFactory` for use with a
//! `MountResolver`. Demonstrates `walk`, `glob`, per-path `PathAttributes` facts, and the
//! name-anomaly report.
//!
//! Run with: cargo run --example browse_ole -- <path-to-a-.doc-or-.msi-or-other-CFBF-file>
//!
//! With no argument, falls back to `artifacts/SampleDoc.doc` if present.

use forensic_rs::core::fs::walk::WalkOptions;
use forensic_rs::prelude::*;
use frnsc_ole::{OleFile, OleFileSystem};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "artifacts/SampleDoc.doc".to_string());
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("could not read '{path}': {e}");
            eprintln!("usage: cargo run --example browse_ole -- <path-to-CFBF-file>");
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
    let fs = OleFileSystem::new(ole);

    println!("== {path}, as a FileSystem ==\n");

    println!("-- walk --");
    for entry in fs.walk(FPath::new(""), &WalkOptions::default()) {
        match entry {
            Ok(entry) => {
                let depth = entry.path.as_str().matches('/').count();
                let leaf = entry.path.file_name().unwrap_or(entry.path.as_str());
                let kind = if entry.file_type == VFileType::Directory { "/" } else { "" };
                let size = entry.metadata.as_ref().map(|m| m.size).unwrap_or(0);
                println!("{}{leaf}{kind}  ({size} bytes)", "  ".repeat(depth));
            }
            Err(e) => println!("  <walk error: {e}>"),
        }
    }

    println!("\n-- glob **/Item (any depth) --");
    for m in fs.glob("**/Item").unwrap_or_default() {
        println!("  {m}");
    }

    println!("\n-- root PathAttributes --");
    if let Some(attrs) = fs.as_attributes() {
        for (key, value) in attrs.attributes(FPath::new("")).unwrap_or_default() {
            println!("  {key} = {value:?}");
        }
    }

    let anomalies: Vec<_> = fs.name_anomalies().collect();
    if !anomalies.is_empty() {
        println!("\n-- name anomalies (excluded from the FileSystem surface) --");
        for (idx, entry, anomaly) in anomalies {
            println!("  [{idx}] {:?} name={:?} -> {anomaly:?}", entry.object_type, entry.name);
        }
    }
}
