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

pub fn extract(page_url: &Url, html: &str) -> PageScripts {
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
    let add = |raw: &str, out: &mut PageScripts| {
        if let Ok(u) = base.join(raw.trim())
            && matches!(u.scheme(), "http" | "https")
            && !out.external.contains(&u)
        {
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
                    out.inline.push(body);
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
        let s = extract(&page, html);
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
        );
        assert_eq!(s.external[0].as_str(), "https://cdn.test/v1/x.js");
    }
}
