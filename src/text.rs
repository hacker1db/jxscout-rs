//! Making untrusted text safe to show in a terminal.
//!
//! URLs, finding values, and log messages come from attacker-controlled
//! JavaScript. Printing them raw would let a script embed ANSI escape
//! sequences (`\x1b[...`) that rewrite your terminal, hide output, or set the
//! window title. Everything shown to a human goes through [`clean`].

use std::borrow::Cow;

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
    }
}
