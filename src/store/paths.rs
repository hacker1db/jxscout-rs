//! Mapping URLs and source-map source names to safe relative paths
//! (SPEC R-31..R-34).
//!
//! Everything returned here is a *relative* path made only of
//! [`sanitize_component`]-ed components, so joining it onto the project
//! directory can never escape it. Decoding happens **before** validation:
//! `%2e%2e%2f` becomes `../` first and is then rejected like a literal `../`.

use std::path::PathBuf;

use percent_encoding::percent_decode_str;
use url::Url;

use crate::events::AssetKind;

/// Max bytes for one path component. Most filesystems allow 255.
const MAX_COMPONENT: usize = 120;

/// File name used for directory-like URLs, e.g. `https://a.test/` (R-31).
pub const INDEX_HTML: &str = "(index).html";

/// Directory holding reversed source-map sources (R-34).
pub const SOURCEMAPS_DIR: &str = "(sourcemaps)";

/// Windows reserved device names. Creating `CON.js` on Windows fails or
/// worse, so these get an underscore prefix everywhere for portability.
const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Turn an arbitrary string into one safe path component, or `None` if
/// nothing meaningful is left (empty, `.`, or `..`).
pub fn sanitize_component(raw: &str) -> Option<String> {
    let mut s: String = raw
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    // Windows silently strips trailing dots and spaces, which could make two
    // different names collide (`a.` vs `a`), so strip them ourselves.
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    if s.is_empty() || s == "." || s == ".." {
        return None;
    }
    let stem = s.split('.').next().unwrap_or_default().to_ascii_lowercase();
    if RESERVED.contains(&stem.as_str()) {
        s.insert(0, '_');
    }
    // Lossy sanitizing would make distinct names collide (`a:b` and `a_b`
    // both become `a_b`), so a changed name gets a short hash of the
    // original. Untouched names stay readable.
    if s != raw {
        s = with_hash_suffix(&s, raw);
    }
    if s.len() > MAX_COMPONENT {
        s = truncate_with_hash(&s);
    }
    Some(s)
}

fn short_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `name.ext` → `name~hash.ext`, hashing `original`.
fn with_hash_suffix(name: &str, original: &str) -> String {
    let hash = short_hash(original);
    match name.rfind('.').filter(|&i| i > 0 && name.len() - i <= 10) {
        Some(i) => format!("{}~{hash}{}", &name[..i], &name[i..]),
        None => format!("{name}~{hash}"),
    }
}

/// Shorten a long name while keeping it unique and keeping its extension.
fn truncate_with_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(s.as_bytes());
    let hash: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let ext = s
        .rfind('.')
        .map(|i| &s[i..])
        .filter(|e| e.len() <= 10)
        .unwrap_or("");
    let mut keep = MAX_COMPONENT - hash.len() - ext.len() - 1;
    while !s.is_char_boundary(keep) {
        keep -= 1;
    }
    format!("{}~{hash}{ext}", &s[..keep])
}

/// The directory name for a URL's host: `host` or `host_port` when the port
/// is not the scheme default.
pub fn host_dir(url: &Url) -> String {
    let host = url.host_str().unwrap_or("unknown-host");
    let name = match url.port() {
        Some(p) => format!("{host}_{p}"),
        None => host.to_string(),
    };
    sanitize_component(&name).unwrap_or_else(|| "unknown-host".into())
}

/// Percent-decode and sanitize every non-empty segment of a URL path.
fn decoded_segments(url: &Url) -> Vec<String> {
    url.path_segments()
        .map(|segs| {
            segs.flat_map(|seg| {
                let decoded = percent_decode_str(seg).decode_utf8_lossy();
                // A decoded segment may now contain `/` (from `%2F`); split
                // on it so `..%2F..` is seen as two `..` components.
                decoded
                    .split(['/', '\\'])
                    .filter_map(sanitize_component)
                    .collect::<Vec<_>>()
            })
            .collect()
        })
        .unwrap_or_default()
}

fn has_extension(name: &str, exts: &[&str]) -> bool {
    let lower = name.to_ascii_lowercase();
    exts.iter().any(|e| lower.ends_with(e))
}

/// Relative path (under the project dir) where an asset at `url` is stored.
///
/// * HTML whose last segment isn't `*.html`/`*.htm` becomes a directory with
///   an `(index).html` inside, so `/app` and `/app/main.js` never fight over
///   whether `app` is a file or a directory (upstream #19).
/// * JS without a JS extension gets `.js` appended so editors highlight it.
pub fn asset_path(url: &Url, kind: AssetKind) -> PathBuf {
    let mut path = PathBuf::from(host_dir(url));
    let mut segs = decoded_segments(url);
    let dir_like = url.path().ends_with('/') || segs.is_empty();

    match kind {
        AssetKind::Html => {
            let last_is_html = segs
                .last()
                .is_some_and(|s| has_extension(s, &[".html", ".htm"]));
            if dir_like || !last_is_html {
                segs.push(INDEX_HTML.into());
            }
        }
        AssetKind::Js | AssetKind::Source => {
            if dir_like {
                segs.push("(index).js".into());
            } else if let Some(last) = segs.last_mut()
                && !has_extension(last, &[".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"])
            {
                last.push_str(".js");
            }
        }
    }
    path.extend(segs);
    path
}

/// Path for the `n`-th inline `<script>` of an HTML page, next to the page
/// and named after it (`page.html.inline-1.js`, `(index).html.inline-1.js`),
/// so two pages in one directory never share an inline script file. A
/// query string makes a different page: it gets a hash in the name.
pub fn inline_script_path(page_url: &Url, n: usize) -> PathBuf {
    let mut p = asset_path(page_url, AssetKind::Html);
    let page_file = p
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let query = page_url
        .query()
        .map(|q| format!("~{}", short_hash(q)))
        .unwrap_or_default();
    let name = sanitize_component(&format!("{page_file}{query}.inline-{n}.js"))
        .unwrap_or_else(|| format!("inline-{n}.js"));
    p.set_file_name(name);
    p
}

/// Path for a reversed source-map source (R-34):
/// `<host>/(sourcemaps)/<bundle path>/<cleaned source path>`.
///
/// Sources are namespaced by the bundle they came from, so two bundles on
/// one host that both contain `src/index.ts` don't overwrite each other.
///
/// Source names look like `webpack://app/./src/App.tsx`,
/// `webpack:///node_modules/x/index.js`, `../../src/a.ts`, or even
/// `/etc/passwd` in a hostile map. Schemes are stripped and `.`/`..`/empty
/// components are dropped, so the result always stays inside the dir.
pub fn sourcemap_source_path(js_url: &Url, source: &str) -> Option<PathBuf> {
    let without_scheme = match source.find("://") {
        Some(i)
            if source[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) =>
        {
            &source[i + 3..]
        }
        _ => source,
    };
    let decoded = percent_decode_str(without_scheme).decode_utf8_lossy();
    let comps: Vec<String> = decoded
        .split(['/', '\\'])
        .filter_map(sanitize_component)
        .collect();
    if comps.is_empty() {
        return None;
    }
    let mut p = PathBuf::from(host_dir(js_url));
    p.push(SOURCEMAPS_DIR);
    let mut bundle = decoded_segments(js_url);
    if bundle.is_empty() {
        bundle.push("(index).js".into());
    }
    if let Some(q) = js_url.query() {
        // `main.js?v=1` and `main.js?v=2` may be different bundles.
        if let Some(last) = bundle.last_mut() {
            *last = format!("{last}~{}", short_hash(q));
        }
    }
    p.extend(bundle);
    p.extend(comps);
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Component, Path};

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn is_safe(p: &Path) -> bool {
        p.components().all(|c| matches!(c, Component::Normal(_)))
    }

    #[test]
    fn basic_layout() {
        assert_eq!(
            asset_path(&u("https://app.test/static/js/main.js?v=1"), AssetKind::Js),
            PathBuf::from("app.test/static/js/main.js")
        );
        assert_eq!(
            asset_path(&u("https://app.test/"), AssetKind::Html),
            PathBuf::from("app.test/(index).html")
        );
        assert_eq!(
            asset_path(&u("http://app.test:8080/login"), AssetKind::Html),
            PathBuf::from("app.test_8080/login/(index).html")
        );
        assert_eq!(
            asset_path(&u("https://app.test/page.html"), AssetKind::Html),
            PathBuf::from("app.test/page.html")
        );
        assert_eq!(
            asset_path(&u("https://app.test/loader"), AssetKind::Js),
            PathBuf::from("app.test/loader.js")
        );
    }

    /// Regression for upstream #19 (`mkdir …/levelblue.com: not a directory`):
    /// a site root page and a script below it never map to file-vs-dir.
    #[test]
    fn root_page_is_a_directory_not_a_file() {
        let page = asset_path(&u("https://levelblue.com"), AssetKind::Html);
        let js = asset_path(&u("https://levelblue.com/a/b.js"), AssetKind::Js);
        assert_eq!(page, PathBuf::from("levelblue.com/(index).html"));
        assert!(js.starts_with("levelblue.com"));
        let app = asset_path(&u("https://x.test/app"), AssetKind::Html);
        let app_js = asset_path(&u("https://x.test/app/main.js"), AssetKind::Js);
        assert_eq!(app.parent(), app_js.parent());
    }

    #[test]
    fn traversal_is_neutralized() {
        for raw in [
            "https://a.test/../../etc/passwd",
            "https://a.test/%2e%2e/%2e%2e/etc/passwd",
            "https://a.test/..%2F..%2Fetc/passwd",
            "https://a.test/..%5C..%5Cwin.ini",
            "https://a.test/%00/x.js",
        ] {
            let p = asset_path(&u(raw), AssetKind::Js);
            assert!(is_safe(&p), "{raw} -> {p:?}");
            assert!(p.starts_with("a.test"), "{raw} -> {p:?}");
        }
    }

    #[test]
    fn sourcemap_sources() {
        let js = u("https://app.test/static/main.js");
        assert_eq!(
            sourcemap_source_path(&js, "webpack://app/./src/App.tsx").unwrap(),
            PathBuf::from("app.test/(sourcemaps)/static/main.js/app/src/App.tsx")
        );
        assert_eq!(
            sourcemap_source_path(&js, "webpack:///node_modules/x/i.js").unwrap(),
            PathBuf::from("app.test/(sourcemaps)/static/main.js/node_modules/x/i.js")
        );
        for hostile in [
            "../../../../etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\x",
            "..\\..\\x",
        ] {
            let p = sourcemap_source_path(&js, hostile).unwrap();
            assert!(is_safe(&p), "{hostile} -> {p:?}");
            assert!(
                p.starts_with("app.test/(sourcemaps)/static/main.js"),
                "{hostile} -> {p:?}"
            );
        }
        assert!(sourcemap_source_path(&js, "../..").is_none());
    }

    /// Independent review #3: inline scripts of different pages and sources
    /// of different bundles never share a path.
    #[test]
    fn inline_and_sourcemap_namespacing() {
        let a = inline_script_path(&u("https://h.test/docs/a.html"), 1);
        let b = inline_script_path(&u("https://h.test/docs/b.html"), 1);
        let root = inline_script_path(&u("https://h.test/docs/"), 1);
        let q1 = inline_script_path(&u("https://h.test/docs/a.html?x=1"), 1);
        assert_eq!(a, PathBuf::from("h.test/docs/a.html.inline-1.js"));
        assert_eq!(root, PathBuf::from("h.test/docs/(index).html.inline-1.js"));
        assert_ne!(a, b);
        assert_ne!(a, q1);

        let m1 = sourcemap_source_path(&u("https://h.test/js/main.js"), "src/index.ts").unwrap();
        let m2 = sourcemap_source_path(&u("https://h.test/js/admin.js"), "src/index.ts").unwrap();
        let m3 =
            sourcemap_source_path(&u("https://h.test/js/main.js?v=2"), "src/index.ts").unwrap();
        assert_ne!(m1, m2);
        assert_ne!(m1, m3);
    }

    #[test]
    fn reserved_and_long_names() {
        assert!(sanitize_component("CON.js").unwrap().starts_with("_CON~"));
        // Lossy sanitizing gets a hash, so distinct raw names stay distinct.
        let a = sanitize_component("a:b").unwrap();
        let b = sanitize_component("a_b").unwrap();
        assert!(a.starts_with("a_b~"), "{a}");
        assert_eq!(b, "a_b");
        assert_ne!(a, b);
        assert_eq!(
            sanitize_component("plain-name.js").unwrap(),
            "plain-name.js"
        );
        let long = format!("{}.js", "x".repeat(500));
        let s = sanitize_component(&long).unwrap();
        assert!(s.len() <= MAX_COMPONENT && s.ends_with(".js"));
        assert_ne!(
            sanitize_component(&format!("{}a.js", "x".repeat(300))),
            sanitize_component(&format!("{}b.js", "x".repeat(300)))
        );
    }

    proptest::proptest! {
        /// Whatever the URL path, the mapped path is relative and safe.
        #[test]
        fn prop_asset_paths_are_safe(path in "(/[a-zA-Z0-9%.\\\\:_-]{0,12}){0,6}") {
            if let Ok(url) = Url::parse(&format!("https://h.test{path}")) {
                for kind in [AssetKind::Js, AssetKind::Html] {
                    let p = asset_path(&url, kind);
                    proptest::prop_assert!(is_safe(&p), "{:?}", p);
                }
            }
        }

        #[test]
        fn prop_sourcemap_paths_are_safe(src in "[a-z:/\\\\.%2eE]{0,40}") {
            let js = Url::parse("https://h.test/a.js").unwrap();
            if let Some(p) = sourcemap_source_path(&js, &src) {
                proptest::prop_assert!(is_safe(&p), "{:?}", p);
                proptest::prop_assert!(p.starts_with("h.test/(sourcemaps)"));
            }
        }
    }
}
