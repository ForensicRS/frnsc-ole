//! Encryption/obfuscation detection for OLE documents -- deliberately detect-and-report only,
//! never decrypt.
//!
//! This module is a stub for now: [MS-OFFCRYPTO] `EncryptionInfo`/`EncryptedPackage` detection
//! and the Word FIB `fEncrypted`/`fObfuscated` flags land alongside Word text extraction (see
//! `AGENTS.md`/`CHANGELOG.md` for why that ordering matters -- text extraction must be able to
//! consult a real answer here before it ships, not silently treat "unchecked" as "not
//! encrypted"). Until then, every document reports [`EncryptionState::NotChecked`], which is the
//! honest state: "this crate does not yet know" is a different, weaker claim than
//! "confirmed not encrypted", and the two must never be conflated.

/// Whether (and how) a document appears to be encrypted or obfuscated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionState {
    /// Actively checked, and no encryption/obfuscation indicator was found.
    NotEncrypted,
    /// An encryption/obfuscation indicator was found.
    Encrypted {
        /// A human-readable name for what was detected (e.g. `"rc4_cryptoapi"`,
        /// `"xor_obfuscation"`), not a normative enumeration -- new schemes should not require
        /// a breaking change here.
        scheme: String,
        /// What was actually observed (e.g. the stream/flag that triggered detection).
        evidence: String,
    },
    /// No check has been performed for this document's format yet. Never merged with
    /// [`EncryptionState::NotEncrypted`] -- "unchecked" and "confirmed clean" are different
    /// claims with different forensic weight.
    NotChecked { reason: &'static str },
}

impl Default for EncryptionState {
    fn default() -> Self {
        EncryptionState::NotChecked {
            reason: "not yet implemented",
        }
    }
}
