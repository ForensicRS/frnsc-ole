//! Reads OLE Compound File Binary Format (CFBF) containers — `.msi`, legacy `.doc`/`.xls`, and
//! other structured-storage files — via `forensic-rs`'s `StructuredObject`/`FormatFactory`
//! traits, matching how `frnsc-hive`/`frnsc-esedb` plug into the same framework.
//!
//! - [`OleFile`] parses a whole CFBF file (header, FAT, mini-FAT, directory tree) and exposes
//!   its streams as `StructuredObject` children, addressed by `LocatorSegment::Stream`.
//! - [`OleFormatFactory`] sniffs and mounts a CFBF file for use with
//!   `forensic_rs::core::resolver::MountResolver`.

mod chain;
mod consts;
mod directory;
mod factory;
mod fat;
mod guid;
mod header;
mod minifat;
mod ole;
mod tree;

pub use directory::{DirectoryEntry, ObjectType};
pub use factory::OleFormatFactory;
pub use header::Header;
pub use ole::OleFile;
