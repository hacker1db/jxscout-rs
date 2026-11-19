//! Extract scripts from HTML pages (SPEC R-40).

use scraper::{Html, Selector};
use url::Url;

/// Scripts referenced or embedded by a page.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PageScripts {
    /// External scripts (`<script src>`, `<link rel=modulepreload>`, …),
    /// resolved and de-duplicated.
    pub external: Vec<Url>,
    /// Inline `<script>` bodies that look like JavaScript.
    pub inline: Vec<String>,
    /// `true` if more scripts were present than `max_scripts` allowed.
    pub truncated: bool,
}

/// Script `type`s that contain JavaScript. Anything else (JSON, templates,
/// import maps) is skipped.
fn is_js_type(t: Option<&str>) -> bool {
    match t.map(|t| t.trim().to_ascii_lowercase()) {
        None => true,
        Some(t) => matches!(
            t.as_str(),
            "" | "module" | "text/javascript" | "application/javascript" | "text/ecmascript"
        ),
    }
}

/// Extract at most `max_scripts` external plus `max_scripts` inline
/// scripts. De-duplication uses a `HashSet`, so a page with thousands of
/// script tags costs linear time, not quadratic.
pub fn extract(page_url: &Url, html: &str, max_scripts: usize) -> PageScripts {
    let doc = Html::parse_document(html);
    // These selectors are constants, so `unwrap` can only fail during
    // development; the unit tests exercise every one.
    let base_sel = Selector::parse("base[href]").unwrap();
    let script_sel = Selector::parse("script").unwrap();
    let link_sel = Selector::parse(
        r#"link[rel="modulepreload"][href], link[rel="preload"][as="script"][href]"#,
    )
    .unwrap();

    // `<base href>` changes how relative URLs resolve.
    let base = doc
        .select(&base_sel)
        .next()
        .and_then(|b| b.value().attr("href"))
        .and_then(|h| page_url.join(h).ok())
        .unwrap_or_else(|| page_url.clone());

    let mut out = PageScripts::default();
    let mut seen = std::collections::HashSet::new();
    let mut add = |raw: &str, out: &mut PageScripts| {
        if let Ok(u) = base.join(raw.trim())
            && matches!(u.scheme(), "http" | "https")
            && !seen.contains(u.as_str())
        {
            if out.external.len() >= max_scripts {
                out.truncated = true;
                return;
            }
            seen.insert(u.as_str().to_string());
            out.external.push(u);
        }
    };

    for el in doc.select(&script_sel) {
        let v = el.value();
        if !is_js_type(v.attr("type")) {
            continue;
        }
        match v.attr("src") {
            Some(src) => add(src, &mut out),
            None => {
                let body: String = el.text().collect();
                if !body.trim().is_empty() {
                    if out.inline.len() >= max_scripts {
                        out.truncated = true;
                    } else {
                        out.inline.push(body);
                    }
                }
            }
        }
    }
    for el in doc.select(&link_sel) {
        if let Some(href) = el.value().attr("href") {
            add(href, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_scripts() {
        let page = Url::parse("https://app.test/dash/").unwrap();
        let html = r#"<html><head>
            <script src="/static/main.js"></script>
            <script src="vendor.js" type="module"></script>
            <script src="/static/main.js"></script>
            <script type="application/json">{"a":1}</script>
            <script type="importmap">{"imports":{}}</script>
            <script>window.config = {api: "/api/v2"};</script>
            <script src="javascript:alert(1)"></script>
            <link rel="modulepreload" href="/assets/chunk-1.js">
            </head></html>"#;
        let s = extract(&page, html, 100);
        let ext: Vec<_> = s.external.iter().map(|u| u.as_str()).collect();
        assert_eq!(
            ext,
            vec![
                "https://app.test/static/main.js",
                "https://app.test/dash/vendor.js",
                "https://app.test/assets/chunk-1.js"
            ]
        );
        assert_eq!(s.inline, vec![r#"window.config = {api: "/api/v2"};"#]);
    }

    #[test]
    fn honours_base_href() {
        let page = Url::parse("https://app.test/a/b").unwrap();
        let s = extract(
            &page,
            r#"<base href="https://cdn.test/v1/"><script src="x.js"></script>"#,
            100,
        );
        assert_eq!(s.external[0].as_str(), "https://cdn.test/v1/x.js");
    }

    /// Independent review #2: many script tags are deduplicated in linear
    /// time and capped.
    #[test]
    fn many_scripts_are_capped_and_deduplicated() {
        let page = Url::parse("https://app.test/").unwrap();
        let mut html = String::new();
        for i in 0..5000 {
            html.push_str(&format!(
                r#"<script src="/s{}.js"></script><script>a{i}()</script>"#,
                i % 3000
            ));
        }
        let start = std::time::Instant::now();
        let s = extract(&page, &html, 500);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(s.external.len(), 500);
        assert_eq!(s.inline.len(), 500);
        assert!(s.truncated);
        let few = extract(
            &page,
            r#"<script src="/a.js"></script><script src="/a.js"></script>"#,
            500,
        );
        assert_eq!(few.external.len(), 1);
        assert!(!few.truncated);
    }
}
