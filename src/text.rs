//! Making untrusted text safe to show in a terminal.
//!
//! URLs, finding values, and log messages come from attacker-controlled
//! JavaScript. Printing them raw would let a script embed ANSI escape
//! sequences (`\x1b[...`) that rewrite your terminal, hide output, or set the
//! window title. Everything shown to a human goes through [`clean`].

use std::borrow::Cow;
use std::fmt;

/// A `Display` wrapper that escapes as it formats:
/// `println!("{}", Clean(&finding.value))`.
pub struct Clean<'a>(pub &'a str);

impl fmt::Display for Clean<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&clean(self.0))
    }
}

/// Restrict a finding category to a safe alphabet. Categories embed names
/// taken from the analyzed code (`Location/Read/<prop>`), so they are
/// validated where they are created, not only when printed.
pub fn category(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || " /_.-$()".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Replace control characters with visible escapes (`\x1b` → `\u{1b}`).
/// Borrows when there is nothing to replace (the common case).
pub fn clean(s: &str) -> Cow<'_, str> {
    if !s.chars().any(is_unsafe) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if is_unsafe(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Control characters plus the Unicode bidi overrides that can visually
/// reorder text ("Trojan Source").
fn is_unsafe(c: char) -> bool {
    c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// An `io::Write` adapter that escapes control and bidi characters in
/// everything written through it, keeping only `\n` and `\t`. Used for the
/// stderr and log-file tracing outputs, as a backstop for any untrusted
/// value that reaches a log line without going through [`clean`].
pub struct SafeWriter<W>(pub W);

impl<W: std::io::Write> std::io::Write for SafeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let mut out = String::with_capacity(text.len());
        for c in text.chars() {
            if (c.is_control() && c != '\n' && c != '\t') || is_unsafe_bidi(c) {
                out.extend(c.escape_unicode());
            } else {
                out.push(c);
            }
        }
        self.0.write_all(out.as_bytes())?;
        // Report the input as fully consumed.
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn is_unsafe_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `tracing_subscriber` writer factory wrapping another one in [`SafeWriter`].
pub struct SafeMakeWriter<M>(pub M);

impl<'a, M: tracing_subscriber::fmt::MakeWriter<'a>> tracing_subscriber::fmt::MakeWriter<'a>
    for SafeMakeWriter<M>
{
    type Writer = SafeWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        SafeWriter(self.0.make_writer())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_sequences() {
        assert!(matches!(clean("plain /api/v1"), Cow::Borrowed(_)));
        let evil = "x\x1b]0;pwned\x07\x1b[2Jy\n";
        let c = clean(evil);
        assert!(!c.chars().any(|c| c.is_control()), "{c}");
        assert_eq!(c, "x\\u{1b}]0;pwned\\u{7}\\u{1b}[2Jy\\u{a}");
        assert!(!clean("a\u{202E}b").contains('\u{202E}'));
        assert_eq!(Clean("a\x1bb").to_string(), "a\\u{1b}b");
    }

    /// Independent review #11: log output escapes CR, ESC, and bidi.
    #[test]
    fn safe_writer_escapes_log_injection() {
        use std::io::Write as _;
        let mut w = SafeWriter(Vec::new());
        write!(w, "url=https://a.test/x\r\x1b[31mFAKE\u{202E}evil\n").unwrap();
        let out = String::from_utf8(w.0).unwrap();
        assert_eq!(
            out,
            "url=https://a.test/x\\u{d}\\u{1b}[31mFAKE\\u{202e}evil\n"
        );
    }

    #[test]
    fn categories_are_restricted() {
        assert_eq!(
            category("Client Behavior/Location/Read/href"),
            "Client Behavior/Location/Read/href"
        );
        assert_eq!(category("Data/x\x1b[31m"), "Data/x__31m");
    }
}
