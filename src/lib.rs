//! Reads OLE Compound File Binary Format (CFBF) containers — `.msi`, legacy `.doc`/`.xls`, and
//! other structured-storage files — and exposes both their raw structure and a typed document
//! view (property sets, document-format identification, and, as later phases land, VBA macros,
//! embedded objects, and Word text) that is bound to no framework trait.
//!
//! - [`OleFileSystem`] is the primary integration surface: a parsed container as an ordinary
//!   `forensic_rs::FileSystem` (storages are directories, streams are files), plus
//!   `forensic_rs::traits::vfs::PathAttributes` for per-path facts. Mounted via
//!   [`OleFileSystemFactory`] for use with `forensic_rs::core::resolver::MountResolver`.
//! - [`OleFile`] parses a whole CFBF file (header, FAT, mini-FAT, directory tree). Also exposes
//!   its streams as `StructuredObject` children (the embedding relationship), mounted via
//!   [`OleFormatFactory`].
//! - [`OleFile::document`] gives the typed [`OleDocument`] view over the same container.
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
mod filesystem;
mod format;
mod guid;
mod header;
mod minifat;
mod names;
mod ole;
pub mod oleps;
mod source;
mod tree;

pub use crypto::EncryptionState;
pub use directory::{DirectoryEntry, ObjectType};
pub use document::OleDocument;
pub use factory::{OleFileSystemFactory, OleFormatFactory};
pub use filesystem::OleFileSystem;
pub use format::{FormatEvidence, FormatIdentity, OleFormat};
pub use header::Header;
pub use names::NameAnomaly;
pub use ole::OleFile;
pub use source::CfbStreams;
