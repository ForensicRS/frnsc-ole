//! Classifies a directory entry's name against what [`crate::OleFile`] can honestly address as
//! a `FileSystem` path.
//!
//! [MS-CFB] 2.6.1 forbids `/`, `\`, `:`, and `!` in a directory entry name -- but `FPath`
//! ([`forensic_rs::core::path`]) treats `/` and `\` as path separators and `X:` as a drive
//! designator. So a name containing one of those characters is simultaneously a spec violation
//! *and* a path-confusion vector: a root-level stream literally named `"A/B"` would produce the
//! same lookup key as a stream named `"B"` inside a storage named `"A"`.
//!
//! The policy this module exists to support is **skip and report**, never reject the whole
//! mount and never escape the name -- see `AGENTS.md` for why. Every character this module
//! flags is exactly what [MS-CFB] 2.6.1 forbids, plus the two purely `FPath`-side hazards
//! (`.`/`..`, which parse as path components rather than names) and an empty name. Nothing
//! beyond that: over-filtering (treating an unusual-but-legal name, e.g. a marker byte or
//! scrambled-Unicode MSI table name, as an anomaly) would silently hide real evidence, which is
//! the actual risk here.

/// Why a directory entry's name cannot be honestly addressed as an `FPath` component.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameAnomaly {
    /// One of the four characters [MS-CFB] 2.6.1 forbids in a name (`/`, `\`, `:`, `!`).
    ForbiddenCharacter(char),
    /// The literal name `"."` or `".."` -- not forbidden by [MS-CFB], but `FPath` parses either
    /// as a path component (`CurDir`/`ParentDir`), not a name, so it cannot address this entry.
    RelativeComponent,
    /// An empty name on an *allocated* (non-[`crate::ObjectType::Unallocated`]) entry.
    Empty,
}

/// [MS-CFB] 2.6.1's forbidden characters, plus the two `!`/`:` special cases OLE itself uses for
/// its own marker/separator conventions (kept forbidden regardless -- a directory entry using
/// them in its *own* name is indistinguishable from OLE's own syntax using them).
const FORBIDDEN: [char; 4] = ['/', '\\', ':', '!'];

/// Classifies `name`. `None` means the name can be trusted as a single `FPath` component.
pub fn classify(name: &str) -> Option<NameAnomaly> {
    if name.is_empty() {
        return Some(NameAnomaly::Empty);
    }
    if name == "." || name == ".." {
        return Some(NameAnomaly::RelativeComponent);
    }
    if let Some(bad) = name.chars().find(|c| FORBIDDEN.contains(c)) {
        return Some(NameAnomaly::ForbiddenCharacter(bad));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_each_forbidden_character() {
        for &c in &FORBIDDEN {
            let name = format!("a{c}b");
            assert_eq!(
                classify(&name),
                Some(NameAnomaly::ForbiddenCharacter(c)),
                "did not flag '{name}'"
            );
        }
    }

    #[test]
    fn flags_relative_components() {
        assert_eq!(classify("."), Some(NameAnomaly::RelativeComponent));
        assert_eq!(classify(".."), Some(NameAnomaly::RelativeComponent));
    }

    #[test]
    fn flags_an_empty_name() {
        assert_eq!(classify(""), Some(NameAnomaly::Empty));
    }

    #[test]
    fn does_not_flag_ordinary_names() {
        assert_eq!(classify("WordDocument"), None);
        assert_eq!(classify("1Table"), None);
        assert_eq!(classify("MsoDataStore"), None);
    }

    /// The negative case that matters most: real-world CFBF names that LOOK unusual but are
    /// entirely legal must never be flagged, or a real document's evidence silently vanishes.
    #[test]
    fn does_not_flag_marker_bytes_or_scrambled_unicode() {
        assert_eq!(classify("\u{1}CompObj"), None); // [MS-CFB] 2.6.1 OLE1 marker
        assert_eq!(classify("\u{5}SummaryInformation"), None); // property-set marker
        assert_eq!(classify("\u{3f3f}\u{4a2b}\u{1234}"), None); // MSI's obfuscated table names
        assert_eq!(classify("   "), None); // whitespace-only is unusual, not forbidden
        assert_eq!(classify("a.b"), None); // an embedded dot is not the same as the literal "."
    }
}
