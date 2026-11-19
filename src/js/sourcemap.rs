//! Source-map discovery and reversal (SPEC R-70..R-74, upstream #13).

use base64::Engine as _;
use percent_encoding::percent_decode_str;
use url::Url;

use crate::model::Headers;

/// Where a source map might be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    /// Fetch this URL.
    Remote { url: Url, why: &'static str },
    /// The map is embedded in the script as a `data:` URI.
    Inline { bytes: Vec<u8> },
}

/// All candidates for `js_url`, in priority order (R-71). The caller tries
/// them in order and keeps the first that validates.
pub fn candidates(js_url: &Url, headers: &Headers, body: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    let push_remote = |out: &mut Vec<Candidate>, raw: &str, why: &'static str| {
        if let Ok(url) = js_url.join(raw.trim())
            && matches!(url.scheme(), "http" | "https")
            && !out
                .iter()
                .any(|c| matches!(c, Candidate::Remote { url: u, .. } if *u == url))
        {
            out.push(Candidate::Remote { url, why });
        }
    };

    for header in ["sourcemap", "x-sourcemap"] {
        if let Some(v) = headers.get(header) {
            push_remote(&mut out, v, "header");
        }
    }
    if let Some(reference) = mapping_url_comment(body) {
        if reference.starts_with("data:") {
            if let Some(bytes) = decode_data_uri(reference) {
                out.push(Candidate::Inline { bytes });
            }
        } else {
            push_remote(&mut out, reference, "comment");
        }
    }
    // Last resort: `<url without query>.map`.
    let mut guess = js_url.clone();
    guess.set_query(None);
    guess.set_fragment(None);
    let guessed = format!("{}.map", guess.path());
    guess.set_path(&guessed);
    push_remote(&mut out, guess.as_str(), "guess");
    out
}

/// The value of the **last** `//# sourceMappingURL=` (or legacy `//@`, or
/// `/*# … */`) comment. Bundlers append it at the end, and earlier matches
/// are often inside string literals of bundled tooling code.
pub fn mapping_url_comment(body: &str) -> Option<&str> {
    const KEY: &str = "sourceMappingURL=";
    let mut search_end = body.len();
    while let Some(idx) = body[..search_end].rfind(KEY) {
        let before = body[..idx].trim_end_matches([' ', '\t']);
        let is_comment = before.ends_with("//#")
            || before.ends_with("//@")
            || before.ends_with("/*#")
            || before.ends_with("/*@");
        if is_comment {
            let rest = &body[idx + KEY.len()..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '*' || c == '\'' || c == '"')
                .unwrap_or(rest.len());
            let value = &rest[..end];
            if !value.is_empty() {
                return Some(value);
            }
        }
        search_end = idx;
    }
    None
}

/// Decode `data:application/json;base64,…` or a percent-encoded `data:` URI.
pub fn decode_data_uri(uri: &str) -> Option<Vec<u8>> {
    let rest = uri.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    if meta.split(';').any(|p| p.eq_ignore_ascii_case("base64")) {
        base64::engine::general_purpose::STANDARD
            .decode(data.trim())
            .ok()
    } else {
        Some(percent_decode_str(data).collect())
    }
}

/// One original file recovered from a map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSource {
    pub name: String,
    pub content: String,
}

/// The result of reversing a map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reversed {
    pub sources: Vec<RecoveredSource>,
    /// Sources listed without `sourcesContent` (R-74: logged, not fatal).
    pub missing_content: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("not a source map: {0}")]
    Invalid(String),
    #[error("source map is valid but contains no sources")]
    Empty,
}

/// Validate bytes as a source map and extract its sources (R-73, R-74).
/// HTML login pages, 404 bodies, and other non-maps are rejected here.
pub fn reverse(bytes: &[u8], max_sources: usize) -> Result<Reversed, MapError> {
    let decoded = sourcemap::decode_slice(bytes).map_err(|e| MapError::Invalid(e.to_string()))?;
    let sm = match decoded {
        sourcemap::DecodedMap::Regular(sm) => sm,
        sourcemap::DecodedMap::Index(idx) => idx
            .flatten()
            .map_err(|e| MapError::Invalid(e.to_string()))?,
        sourcemap::DecodedMap::Hermes(h) => (*h).clone(),
    };
    let mut out = Reversed::default();
    for (i, name) in sm.sources().enumerate().take(max_sources) {
        match sm.get_source_contents(i as u32) {
            Some(content) => out.sources.push(RecoveredSource {
                name: name.to_string(),
                content: content.to_string(),
            }),
            None => out.missing_content.push(name.to_string()),
        }
    }
    if out.sources.is_empty() && out.missing_content.is_empty() {
        return Err(MapError::Empty);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = r#"{"version":3,"sources":["webpack://app/./src/a.js"],"sourcesContent":["export const a = 1;\n"],"names":[],"mappings":"AAAA"}"#;

    fn js() -> Url {
        Url::parse("https://app.test/static/main.js?v=3").unwrap()
    }

    #[test]
    fn candidate_order_and_dedup() {
        let mut h = Headers::new();
        h.push("SourceMap", "/maps/main.js.map");
        h.push("X-SourceMap", "/maps/main.js.map"); // duplicate
        let body = "console.log(1)\n//# sourceMappingURL=main.js.map\n";
        let c = candidates(&js(), &h, body);
        let urls: Vec<_> = c
            .iter()
            .map(|c| match c {
                Candidate::Remote { url, why } => format!("{why}:{url}"),
                Candidate::Inline { .. } => "inline".into(),
            })
            .collect();
        assert_eq!(
            urls,
            vec![
                "header:https://app.test/maps/main.js.map",
                "comment:https://app.test/static/main.js.map",
            ],
            "the guess equals the comment URL, so it's deduplicated"
        );
    }

    #[test]
    fn guess_strips_query() {
        let c = candidates(&js(), &Headers::new(), "no comment");
        assert_eq!(
            c,
            vec![Candidate::Remote {
                url: Url::parse("https://app.test/static/main.js.map").unwrap(),
                why: "guess"
            }]
        );
    }

    #[test]
    fn inline_base64_and_percent_encoded() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(MAP);
        let body =
            format!("x()\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,{b64}\n");
        let c = candidates(&js(), &Headers::new(), &body);
        assert!(matches!(&c[0], Candidate::Inline { bytes } if bytes == MAP.as_bytes()));

        let pct = format!(
            "data:application/json,{}",
            MAP.replace('"', "%22").replace(' ', "%20")
        );
        assert_eq!(decode_data_uri(&pct).unwrap(), MAP.as_bytes());
    }

    #[test]
    fn last_comment_wins_and_strings_are_ignored() {
        let body = r#"var s = "sourceMappingURL=bogus.map"; //# sourceMappingURL=first.map
x();
//# sourceMappingURL=real.map"#;
        assert_eq!(mapping_url_comment(body), Some("real.map"));
        assert_eq!(
            mapping_url_comment("/*# sourceMappingURL=a.map */"),
            Some("a.map")
        );
        assert_eq!(
            mapping_url_comment("//@ sourceMappingURL=old.map"),
            Some("old.map")
        );
        assert_eq!(mapping_url_comment(r#"x = "sourceMappingURL=no";"#), None);
    }

    #[test]
    fn reverse_valid_and_invalid() {
        let r = reverse(MAP.as_bytes(), 100).unwrap();
        assert_eq!(r.sources.len(), 1);
        assert_eq!(r.sources[0].name, "webpack://app/./src/a.js");
        // An HTML login page is not a map (upstream #13 / #31).
        assert!(matches!(
            reverse(b"<html>Please log in</html>", 100),
            Err(MapError::Invalid(_))
        ));
        let no_content = r#"{"version":3,"sources":["a.js"],"names":[],"mappings":""}"#;
        let r = reverse(no_content.as_bytes(), 100).unwrap();
        assert_eq!(r.missing_content, vec!["a.js"]);
    }

    #[test]
    fn reverse_respects_max_sources() {
        let many = r#"{"version":3,"sources":["a","b","c"],"sourcesContent":["1","2","3"],"names":[],"mappings":""}"#;
        assert_eq!(reverse(many.as_bytes(), 2).unwrap().sources.len(), 2);
    }
}
