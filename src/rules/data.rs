//! "Data" rules: paths, URLs, hostnames, query strings, extensions, MIME
//! types, regexes, and GraphQL documents.

use std::sync::LazyLock;

use oxc_ast::AstKind;
use oxc_ast::ast::Expression;
use oxc_span::Span;
use regex::Regex;

use super::{Rule, RuleContext};
use crate::js::{member_path, string_value};

/// Text of string literals and templates (templates rendered with `${…}`).
/// Template quasis are covered by their parent `TemplateLiteral`.
pub(super) fn string_like(node: AstKind<'_>) -> Option<(Span, String)> {
    match node {
        AstKind::StringLiteral(s) => Some((s.span, s.value.display().to_string())),
        AstKind::TemplateLiteral(t) => {
            let mut out = String::new();
            for (i, q) in t.quasis.iter().enumerate() {
                out.push_str(q.value.raw.as_str());
                if i < t.expressions.len() {
                    out.push_str("${…}");
                }
            }
            Some((t.span, out))
        }
        _ => None,
    }
}

// `LazyLock` compiles each regex once, the first time it is used.
static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^(?i)(https?|wss?)://[^\s"'<>]+$"#).unwrap());
static PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(/|\./|\.\./)[A-Za-z0-9_\-./~%:@!$&'()*+,;=?#{}…\[\]]*$").unwrap()
});
static API_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)/(api|rest|graphql|gql|rpc|v[0-9]+)(/|$|\?)").unwrap());
static EXT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(json|xml|php|aspx?|jsp|env|bak|old|sql|zip|tar|gz|config|ya?ml|txt|log|csv|pdf|docx?|xlsx?|wasm)(\?|#|$)")
        .unwrap()
});
static MIME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(application|text|image|audio|video|multipart|font)/[A-Za-z0-9][A-Za-z0-9.+\-]*$")
        .unwrap()
});
/// A bare hostname. The TLD must be one of a curated list, otherwise
/// every dotted identifier (`user.name`, `config.json`) would match.
static HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+",
        r"(?:com|net|org|io|dev|app|co|ai|gov|edu|mil|info|biz|me|us|uk|de|fr|nl|jp|cn|ru|br|in|au|ca|eu|",
        r"xyz|cloud|tech|site|online|test|local|internal|corp|lan|cloudfront\.net|amazonaws\.com)$"
    ))
    .unwrap()
});
static GRAPHQL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(query|mutation|subscription|fragment)\b[^{]*\{").unwrap());

/// Paths, URLs, hostnames, query strings, extensions, MIME types.
pub struct StringsRule;

impl Rule for StringsRule {
    fn id(&self) -> &'static str {
        "strings"
    }
    fn description(&self) -> &'static str {
        "URL paths, API paths, full URLs, hostnames, query params, file extensions, MIME types"
    }
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
        let Some((span, text)) = string_like(node) else {
            return;
        };
        let text = text.trim();
        if text.len() < 2 || text.len() > 2048 {
            return;
        }

        let is_url = URL_RE.is_match(text);
        let is_path = !is_url
            && !text.starts_with("//")
            && PATH_RE.is_match(text)
            && text.chars().any(|c| c.is_ascii_alphabetic());

        if is_url {
            cx.report(span, "Data/Paths/URL", text);
            if let Ok(u) = url::Url::parse(&text.replace("${…}", "x")) {
                if let Some(h) = u.host_str() {
                    cx.report(span, "Data/Hostname", h);
                }
                if API_RE.is_match(u.path()) {
                    cx.report(span, "Data/Paths/API", u.path());
                }
            }
        } else if is_path {
            let category = if API_RE.is_match(text) {
                "Data/Paths/API"
            } else {
                "Data/Paths/Paths"
            };
            cx.report(span, category, text);
        } else if MIME_RE.is_match(text) {
            cx.report(span, "Data/MIME Type", text);
            return;
        } else if HOST_RE.is_match(text) {
            cx.report(span, "Data/Hostname", text.to_ascii_lowercase());
            return;
        } else {
            return;
        }

        // Extra facets of URL-ish strings.
        if let Some((_, query)) = text.split_once('?') {
            let query = query.split('#').next().unwrap_or_default();
            let names: Vec<&str> = query
                .split('&')
                .filter_map(|kv| kv.split('=').next())
                .filter(|k| !k.is_empty())
                .collect();
            if !names.is_empty() {
                cx.report(span, "Data/Paths/Query", names.join(","));
            }
        }
        if let Some(frag) = text
            .split_once('#')
            .map(|(_, f)| f)
            .filter(|f| f.starts_with('/'))
        {
            cx.report(span, "Data/Paths/Fragment", frag);
        }
        if let Some(c) = EXT_RE.captures(text) {
            cx.report(
                span,
                format!("Data/Extensions/{}", c[1].to_ascii_lowercase()),
                text,
            );
        }
    }
}

/// Regex literals, `new RegExp(…)`, and regexes passed to `match/test/…`.
pub struct RegexRule;

impl Rule for RegexRule {
    fn id(&self) -> &'static str {
        "regex"
    }
    fn description(&self) -> &'static str {
        "Regular expressions (often encode validation and routing logic)"
    }
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
        match node {
            AstKind::RegExpLiteral(r) => {
                cx.report(r.span, "Data/Regex/Pattern", cx.snippet(r.span))
            }
            AstKind::NewExpression(n) if member_path(&n.callee).as_deref() == Some("RegExp") => {
                if let Some(p) = n
                    .arguments
                    .first()
                    .and_then(|a| a.as_expression())
                    .and_then(string_value)
                {
                    cx.report(n.span, "Data/Regex/Pattern", p);
                }
            }
            AstKind::CallExpression(c) => {
                let Some(path) = member_path(&c.callee) else {
                    return;
                };
                let method = crate::js::last_segment(&path);
                let first_is_regex = matches!(
                    c.arguments.first().and_then(|a| a.as_expression()),
                    Some(Expression::RegExpLiteral(_))
                );
                if first_is_regex
                    && matches!(
                        method,
                        "match" | "matchAll" | "replace" | "replaceAll" | "split" | "search"
                    )
                {
                    cx.report(c.span, "Data/Regex/Match", cx.snippet(c.span));
                }
            }
            _ => {}
        }
    }
}

/// GraphQL queries, mutations, and fragments in strings or `gql` tags.
pub struct GraphQlRule;

impl Rule for GraphQlRule {
    fn id(&self) -> &'static str {
        "graphql"
    }
    fn description(&self) -> &'static str {
        "GraphQL operations embedded in strings or gql`` templates"
    }
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
        if let AstKind::TaggedTemplateExpression(t) = node {
            let tag = member_path(&t.tag).unwrap_or_default();
            if matches!(tag.as_str(), "gql" | "graphql") {
                let Some((_, text)) = string_like(AstKind::TemplateLiteral(&t.quasi)) else {
                    return;
                };
                if !GRAPHQL_RE.is_match(&text) {
                    // Shorthand `{ me { id } }` queries have no keyword.
                    cx.report(t.span, "Data/GraphQL/Query", text.trim());
                }
            }
            return;
        }
        let Some((span, text)) = string_like(node) else {
            return;
        };
        if let Some(c) = GRAPHQL_RE.captures(&text) {
            let category = match &c[1] {
                "query" => "Data/GraphQL/Query",
                "mutation" => "Data/GraphQL/Mutation",
                _ => "Data/GraphQL/Other",
            };
            cx.report(span, category, text.trim());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{has, run};
    use super::*;

    #[test]
    fn paths_urls_and_facets() {
        let f = run(
            StringsRule,
            r#"const a = "/api/v2/users?id=1&debug=true"; const b = "https://cdn.app.test/x/config.json";
               const c = "./relative/page"; const d = "application/json"; const e = "hello world";
               const g = `/users/${id}/edit`; const h = "/#/admin/settings"; const i = "//not-a-path";"#,
        );
        assert!(has(&f, "Data/Paths/API", "/api/v2/users?id=1&debug=true"));
        assert!(has(&f, "Data/Paths/Query", "id,debug"));
        assert!(has(
            &f,
            "Data/Paths/URL",
            "https://cdn.app.test/x/config.json"
        ));
        assert!(has(&f, "Data/Hostname", "cdn.app.test"));
        assert!(has(
            &f,
            "Data/Extensions/json",
            "https://cdn.app.test/x/config.json"
        ));
        assert!(has(&f, "Data/Paths/Paths", "./relative/page"));
        assert!(has(&f, "Data/MIME Type", "application/json"));
        assert!(has(&f, "Data/Paths/Paths", "/users/${…}/edit"));
        assert!(has(&f, "Data/Paths/Fragment", "/admin/settings"));
        assert!(
            !f.iter()
                .any(|(_, v)| v == "hello world" || v == "//not-a-path")
        );
    }

    /// Codex M3 #10: standalone hostnames, without dotted-identifier noise.
    #[test]
    fn standalone_hostnames() {
        let f = run(
            StringsRule,
            r#"const a = "api.example.com"; const b = "internal.corp"; const c = "user.name";
               const d = "config.json"; const e = "app.bundle.js";"#,
        );
        assert!(has(&f, "Data/Hostname", "api.example.com"));
        assert!(has(&f, "Data/Hostname", "internal.corp"));
        assert_eq!(
            f.iter().filter(|(c, _)| c == "Data/Hostname").count(),
            2,
            "{f:?}"
        );
    }

    #[test]
    fn regexes() {
        let f = run(
            RegexRule,
            r#"const r = /^[a-z]+$/i; new RegExp("\\d+"); s.match(/x(y)/);"#,
        );
        assert!(has(&f, "Data/Regex/Pattern", "/^[a-z]+$/i"));
        assert!(has(&f, "Data/Regex/Pattern", "\\d+"));
        assert!(has(&f, "Data/Regex/Match", "s.match(/x(y)/)"));
    }

    #[test]
    fn graphql() {
        let f = run(
            GraphQlRule,
            r#"const q = "query GetUser($id: ID!) { user(id: $id) { email } }";
               const m = `mutation { deleteUser(id: 1) }`;
               const s = gql`{ me { id } }`;"#,
        );
        assert!(
            f.iter()
                .any(|(c, v)| c == "Data/GraphQL/Query" && v.starts_with("query GetUser"))
        );
        assert!(f.iter().any(|(c, _)| c == "Data/GraphQL/Mutation"));
        assert!(has(&f, "Data/GraphQL/Query", "{ me { id } }"));
    }
}
