//! Scope matching (SPEC R-20..R-24).
//!
//! A scope is a list of wildcard patterns. `*` matches any run of characters
//! (including none); every other character matches itself, case-insensitively.
//!
//! * patterns **without** `/` are matched against the URL host,
//! * patterns **with** `/` are matched against the whole URL (minus fragment),
//! * patterns prefixed with `!` are exclusions and always win (R-22a).

use std::fmt;
use std::path::Path;

use url::Url;

/// One parsed scope pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// The pattern as the user wrote it (without the leading `!`).
    raw: String,
    /// Lower-cased glob used for matching.
    glob: String,
    /// `true` when the pattern is matched against the full URL.
    full_url: bool,
}

impl Pattern {
    fn new(raw: &str) -> Self {
        Self {
            raw: raw.to_string(),
            glob: raw.to_ascii_lowercase(),
            full_url: raw.contains('/'),
        }
    }

    fn matches(&self, url: &Url) -> bool {
        if self.full_url {
            let mut u = url.clone();
            u.set_fragment(None);
            wildcard_match(&self.glob, &u.as_str().to_ascii_lowercase())
        } else {
            let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
            wildcard_match(&self.glob, &host)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// Why [`Scope::check`] accepted or rejected a URL. Carried into debug logs
/// so users can see *which* request was dropped and why (R-24, upstream #9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No positive patterns configured: everything not excluded is in scope.
    InScopeByDefault,
    /// Matched this positive pattern.
    Included(String),
    /// Matched this exclusion pattern.
    Excluded(String),
    /// Positive patterns exist and none matched.
    NoMatch,
}

impl Decision {
    pub fn is_in(&self) -> bool {
        matches!(self, Self::InScopeByDefault | Self::Included(_))
    }

    pub fn is_excluded(&self) -> bool {
        matches!(self, Self::Excluded(_))
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InScopeByDefault => f.write_str("in scope (no scope configured)"),
            Self::Included(p) => write!(f, "in scope (matched `{p}`)"),
            Self::Excluded(p) => write!(f, "excluded by `!{p}`"),
            Self::NoMatch => f.write_str("no scope pattern matched"),
        }
    }
}

/// A set of include and exclude patterns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    include: Vec<Pattern>,
    exclude: Vec<Pattern>,
}

impl Scope {
    /// Build a scope from individual patterns. Each item may itself be a
    /// comma-separated list, so `--scope a,b --scope c` works as expected.
    pub fn from_patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut scope = Self::default();
        for item in patterns {
            for p in item.as_ref().split(',') {
                scope.add(p);
            }
        }
        scope
    }

    /// Parse scope file contents: one pattern per line, blank lines and `#`
    /// comments ignored (R-21, upstream #8).
    pub fn parse_file_contents(contents: &str) -> Self {
        let mut scope = Self::default();
        for line in contents.lines() {
            let line = line.split('#').next().unwrap_or_default();
            scope.add(line);
        }
        scope
    }

    /// Read and parse a scope file.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        Ok(Self::parse_file_contents(&std::fs::read_to_string(path)?))
    }

    /// Merge another scope into this one.
    pub fn merge(&mut self, other: Scope) {
        self.include.extend(other.include);
        self.exclude.extend(other.exclude);
    }

    fn add(&mut self, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() {
            return;
        }
        match raw.strip_prefix('!') {
            Some(neg) if !neg.trim().is_empty() => self.exclude.push(Pattern::new(neg.trim())),
            Some(_) => {}
            None => self.include.push(Pattern::new(raw)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    pub fn includes(&self) -> impl Iterator<Item = &Pattern> {
        self.include.iter()
    }

    pub fn excludes(&self) -> impl Iterator<Item = &Pattern> {
        self.exclude.iter()
    }

    /// Decide whether `url` is in scope.
    pub fn check(&self, url: &Url) -> Decision {
        if let Some(p) = self.exclude.iter().find(|p| p.matches(url)) {
            return Decision::Excluded(p.raw.clone());
        }
        if self.include.is_empty() {
            return Decision::InScopeByDefault;
        }
        match self.include.iter().find(|p| p.matches(url)) {
            Some(p) => Decision::Included(p.raw.clone()),
            None => Decision::NoMatch,
        }
    }

    /// Shorthand for `self.check(url).is_in()`.
    pub fn is_in(&self, url: &Url) -> bool {
        self.check(url).is_in()
    }
}

/// Glob matching where `*` matches any sequence of characters.
///
/// This is the classic greedy two-pointer algorithm: walk both strings, and
/// when a `*` is seen remember where it was so that on a later mismatch we
/// can "backtrack" by letting the star swallow one more character. It runs in
/// O(pattern × text) worst case and needs no allocation.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Position of the last `*` in the pattern, and the text index it was at.
    let mut star: Option<(usize, usize)> = None;

    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            // Let the star absorb one more character and retry.
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    // Any trailing stars match the empty string.
    p[pi..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn wildcard_basics() {
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*.example.com", "app.example.com"));
        assert!(!wildcard_match("*.example.com", "example.com"));
        assert!(wildcard_match("*example*", "my-example-site"));
        assert!(wildcard_match("a*b*c", "aXXbYYc"));
        assert!(!wildcard_match("a*b*c", "aXXbYY"));
        assert!(wildcard_match("exact.com", "exact.com"));
        assert!(!wildcard_match("exact.com", "exact.co"));
    }

    #[test]
    fn empty_scope_accepts_everything() {
        let s = Scope::default();
        assert_eq!(s.check(&u("https://x.test/")), Decision::InScopeByDefault);
    }

    #[test]
    fn host_patterns_are_case_insensitive() {
        let s = Scope::from_patterns(["*.Target1.com"]);
        assert!(s.is_in(&u("https://APP.target1.com/a.js")));
        assert!(!s.is_in(&u("https://evil.com/?q=.target1.com")));
    }

    #[test]
    fn url_patterns_match_full_url() {
        let s = Scope::from_patterns(["https://cdn.test/app/*"]);
        assert!(s.is_in(&u("https://cdn.test/app/main.js")));
        assert!(!s.is_in(&u("https://cdn.test/other/main.js")));
    }

    #[test]
    fn exclusions_win() {
        let s = Scope::from_patterns(["*.example.com,!ads.example.com"]);
        assert!(s.is_in(&u("https://www.example.com/")));
        assert_eq!(
            s.check(&u("https://ads.example.com/x.js")),
            Decision::Excluded("ads.example.com".into())
        );
    }

    #[test]
    fn negative_only_scope_means_everything_else() {
        let s = Scope::from_patterns(["!*.google.com"]);
        assert!(s.is_in(&u("https://target.test/")));
        assert!(!s.is_in(&u("https://maps.google.com/")));
    }

    /// Regression for upstream #8: scope can come from a file.
    #[test]
    fn scope_file_format() {
        let s = Scope::parse_file_contents(
            "# targets\n*.target1.com\n\n*.target2.*   # trailing comment\ntarget3.com\n!static.target1.com\n",
        );
        assert_eq!(s.includes().count(), 3);
        assert_eq!(s.excludes().count(), 1);
        assert!(s.is_in(&u("https://a.target2.net/")));
        assert!(s.is_in(&u("https://target3.com/")));
        assert!(!s.is_in(&u("https://static.target1.com/")));
    }

    /// Regression for upstream #9: the decision explains itself.
    #[test]
    fn decision_display_names_the_rule() {
        let s = Scope::from_patterns(["*.a.com"]);
        assert_eq!(
            s.check(&u("https://b.com/")).to_string(),
            "no scope pattern matched"
        );
    }

    proptest::proptest! {
        /// A pattern equal to the text (with no `*`) always matches, and
        /// `*` + any suffix of the text matches.
        #[test]
        fn prop_literal_and_suffix(text in "[a-z.]{0,20}", cut in 0usize..20) {
            proptest::prop_assert!(wildcard_match(&text, &text));
            let cut = cut.min(text.len());
            let pat = format!("*{}", &text[cut..]);
            proptest::prop_assert!(wildcard_match(&pat, &text));
        }
    }
}
