//! Reads OLE Compound File Binary Format (CFBF) containers — `.msi`, legacy `.doc`/`.xls`, and
//! other structured-storage files — via `forensic-rs`'s `StructuredObject`/`FormatFactory`
//! traits, matching how `frnsc-hive`/`frnsc-esedb` plug into the same framework, and on top of
//! that, a typed document view bound to no framework trait: property sets, document-format
//! identification, and (as later phases land) VBA macros, embedded objects, and Word text.
//!
//! - [`OleFile`] parses a whole CFBF file (header, FAT, mini-FAT, directory tree) and exposes
//!   its streams as `StructuredObject` children, addressed by `LocatorSegment::Stream`.
//! - [`OleFile::document`] gives the typed [`OleDocument`] view over the same container.
//! - [`OleFormatFactory`] sniffs and mounts a CFBF file for use with
//!   `forensic_rs::core::resolver::MountResolver`.
//!
//! This crate is deliberately **primitives only**: it extracts facts (property values, macro
//! source, embedded files, document text) and ships no malware detection, keyword matching, or
//! scoring. Build that downstream, on top of what this crate surfaces.

mod chain;
mod consts;
mod crypto;
mod directory;
mod document;
mod factory;
mod fat;
mod format;
mod guid;
mod header;
mod minifat;
mod ole;
pub mod oleps;
mod source;
mod tree;

pub use crypto::EncryptionState;
pub use directory::{DirectoryEntry, ObjectType};
pub use document::OleDocument;
pub use factory::OleFormatFactory;
pub use format::{FormatEvidence, FormatIdentity, OleFormat};
pub use header::Header;
pub use ole::OleFile;
pub use source::CfbStreams;
