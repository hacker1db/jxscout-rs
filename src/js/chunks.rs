//! Webpack and Vite chunk discovery without running any JavaScript
//! (SPEC R-50..R-54).
//!
//! ## Webpack
//!
//! Webpack's runtime contains a "chunk filename" function. Minified, it
//! looks like one of:
//!
//! ```js
//! r.u = e => "static/js/" + e + "." + {12:"a1b2",34:"c3d4"}[e] + ".chunk.js"
//! function u(e){return n.p+""+({5:"vendors"}[e]||e)+"."+{5:"9f8e"}[e]+".js"}
//! ```
//!
//! Upstream ran this code in Bun. We instead *statically evaluate* the
//! returned expression with a tiny interpreter ([`Evaluator`]) that knows
//! only: string/number literals, the parameter, `+`, template literals,
//! `{…}[param]` lookups, `a || b`, `p === k ? a : b`, and `x.p` (the public
//! path). The keys of the `{…}` tables are the chunk ids; evaluating the
//! expression once per id yields every chunk filename. If the expression
//! uses the parameter but has no tables, ids `0..limit` are brute-forced
//! (R-52).
//!
//! ## Vite / native ESM
//!
//! Chunks are referenced with plain `import("./x.js")`, `import … from`,
//! and preload dependency arrays like `["assets/a.js","assets/a.css"]`.
//! Those are collected as strings and resolved per R-53.

use std::collections::{BTreeMap, BTreeSet};

use oxc_ast::ast::{
    ArrayExpressionElement, ArrowFunctionExpression, AssignmentTarget, BinaryOperator,
    BindingPattern, Expression, FormalParameters, Function, LogicalOperator, ObjectExpression,
    ObjectPropertyKind, Program, PropertyKey, Statement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk;
use url::Url;

/// Discovered chunk URLs and how they were found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// Absolute, de-duplicated, in discovery order.
    pub urls: Vec<Url>,
    /// `true` if any URLs came from brute-forcing numeric ids.
    pub bruteforced: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub bruteforce: u32,
    pub max_urls: usize,
}

/// Find chunk URLs in a parsed script located at `script_url`.
pub fn discover(program: &Program<'_>, script_url: &Url, limits: Limits) -> Discovery {
    let mut v = Collector::new(limits);
    v.visit_program(program);

    let public_path = v
        .public_paths
        .iter()
        .find(|p| looks_like_public_path(p))
        .cloned();
    let mut out = Discovery::default();
    let mut seen = BTreeSet::new();
    let mut push = |url: Url, out: &mut Discovery| {
        if out.urls.len() < limits.max_urls && seen.insert(url.to_string()) {
            out.urls.push(url);
            true
        } else {
            false
        }
    };

    // Explicit references first, so heuristic webpack candidates can't
    // crowd them out of the URL budget.
    for spec in &v.esm_specifiers {
        if let Some(url) = resolve_esm(script_url, spec) {
            push(url, &mut out);
        }
    }
    // Preload dependency arrays: relative to the Vite base (origin root).
    for dep in &v.preload_deps {
        if let Some(url) = resolve_preload(script_url, dep) {
            push(url, &mut out);
        }
    }
    // Webpack chunk filenames.
    for (name, brute) in &v.webpack_names {
        if let Some(url) = resolve_webpack(script_url, public_path.as_deref(), name)
            && push(url, &mut out)
        {
            out.bruteforced |= *brute;
        }
    }
    out
}

fn is_js_path(s: &str) -> bool {
    let path = s.split(['?', '#']).next().unwrap_or(s);
    [".js", ".mjs", ".cjs"].iter().any(|e| path.ends_with(e))
}

/// Plausible `__webpack_require__.p` values: absolute URLs, root paths, or
/// relative directory prefixes. Webpack's `"auto"` is resolved at runtime,
/// so it is ignored (we fall back to the script location).
fn looks_like_public_path(p: &str) -> bool {
    p.is_empty()
        || p.starts_with('/')
        || p.starts_with("http://")
        || p.starts_with("https://")
        || (p.ends_with('/') && !p.contains(char::is_whitespace))
}

/// Resolve a webpack chunk filename.
///
/// * absolute names are used as-is;
/// * with a public path, `public_path + name` is resolved against the script;
/// * without one, webpack's "auto" public path is the script's directory, but
///   bundles like CRA emit names such as `static/js/1.chunk.js` relative to
///   the *site root*. If the name's leading directories appear in the script
///   path (`/app/static/js/main.js`), resolve against the part before them.
pub fn resolve_webpack(script_url: &Url, public_path: Option<&str>, name: &str) -> Option<Url> {
    if name.starts_with("http://") || name.starts_with("https://") || name.starts_with("//") {
        return script_url.join(name).ok();
    }
    if let Some(pp) = public_path.filter(|p| !p.is_empty()) {
        // Webpack builds the URL by plain string concatenation:
        // `__webpack_require__.p + filename`. A relative public path is
        // relative to the page; we approximate with the script URL.
        return script_url.join(&format!("{pp}{name}")).ok();
    }
    if name.starts_with('/') {
        return script_url.join(name).ok();
    }
    let dir_part = name.rsplit_once('/').map(|(d, _)| d);
    if let Some(dir) = dir_part {
        let needle = format!("/{dir}/");
        if let Some(idx) = script_url.path().find(&needle) {
            let mut base = script_url.clone();
            base.set_path(&script_url.path()[..idx + 1]);
            base.set_query(None);
            return base.join(name).ok();
        }
    }
    script_url.join(name).ok()
}

/// Resolve an ESM import specifier (R-53). Bare specifiers return `None`.
pub fn resolve_esm(script_url: &Url, spec: &str) -> Option<Url> {
    let is_url = spec.starts_with("http://") || spec.starts_with("https://");
    let is_relative = spec.starts_with("./") || spec.starts_with("../") || spec.starts_with('/');
    if !(is_url || is_relative) {
        return None;
    }
    // `./bootstrap` (no extension) is a valid module URL; `./styles.css`
    // or `./data.json` imports are not scripts.
    let path = spec.split(['?', '#']).next().unwrap_or(spec);
    let last = path.rsplit('/').next().unwrap_or(path);
    if last.contains('.') && !is_js_path(spec) {
        return None;
    }
    script_url.join(spec).ok()
}

fn resolve_preload(script_url: &Url, dep: &str) -> Option<Url> {
    if !is_js_path(dep) {
        return None;
    }
    if dep.starts_with("./")
        || dep.starts_with("../")
        || dep.contains("://")
        || dep.starts_with('/')
    {
        return resolve_esm(script_url, dep);
    }
    // `assets/x.js` → relative to the origin root.
    script_url.join(&format!("/{dep}")).ok()
}

// ---------------------------------------------------------------------------
// The collector (an AST visitor)
// ---------------------------------------------------------------------------

/// Walks the AST once and records everything chunk-related.
///
/// Chunk-name functions are evaluated *while visiting* rather than stored
/// for later: the `Visit` trait hands out short-lived borrows of each node,
/// so keeping `&Expression` around past the callback would not borrow-check.
/// Evaluating immediately and storing owned `String`s sidesteps that.
struct Collector {
    limits: Limits,
    public_paths: Vec<String>,
    /// Evaluated chunk filenames, and whether they came from brute force.
    webpack_names: Vec<(String, bool)>,
    /// De-duplicates `webpack_names`.
    names_seen: BTreeSet<String>,
    /// Total evaluations so far; bounded so a script full of one-argument
    /// string formatters can't burn CPU (R-36).
    evaluations: usize,
    esm_specifiers: Vec<String>,
    preload_deps: Vec<String>,
}

impl Collector {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            public_paths: Vec::new(),
            webpack_names: Vec::new(),
            names_seen: BTreeSet::new(),
            evaluations: 0,
            esm_specifiers: Vec::new(),
            preload_deps: Vec::new(),
        }
    }

    /// If `expr` (the return value of a one-parameter function) builds a
    /// chunk filename, evaluate it for every chunk id.
    fn consider(&mut self, param: &str, expr: &Expression<'_>) {
        let mut info = ExprInfo::default();
        info.scan(expr, param);
        if !(info.uses_param && info.has_js_literal) {
            return;
        }
        let brute = info.keys.is_empty();
        let ids: Box<dyn Iterator<Item = String>> = if brute {
            Box::new((0..self.limits.bruteforce).map(|n| n.to_string()))
        } else {
            Box::new(info.keys.into_iter())
        };
        let budget = self.limits.max_urls + self.limits.bruteforce as usize;
        for id in ids {
            if self.webpack_names.len() >= self.limits.max_urls || self.evaluations >= budget {
                break;
            }
            self.evaluations += 1;
            let ev = Evaluator { param, key: &id };
            if let Some(name) = ev.eval(expr)
                && is_js_path(&name)
                && self.names_seen.insert(name.clone())
            {
                self.webpack_names.push((name, brute));
            }
        }
    }

    fn consider_statements(&mut self, param: &str, stmts: &[Statement<'_>]) {
        for stmt in stmts {
            if let Statement::ReturnStatement(r) = stmt
                && let Some(arg) = &r.argument
            {
                self.consider(param, arg);
            }
        }
    }
}

/// The single identifier parameter of a function, if that's what it has.
fn single_param(params: &FormalParameters<'_>) -> Option<String> {
    if params.items.len() != 1 || params.rest.is_some() {
        return None;
    }
    match &params.items[0].pattern {
        BindingPattern::BindingIdentifier(id) => Some(id.name.to_string()),
        _ => None,
    }
}

impl<'a> Visit<'a> for Collector {
    fn visit_function(&mut self, f: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
        if let (Some(param), Some(body)) = (single_param(&f.params), &f.body) {
            self.consider_statements(&param, &body.statements);
        }
        walk::walk_function(self, f, flags);
    }

    fn visit_arrow_function_expression(&mut self, f: &ArrowFunctionExpression<'a>) {
        if let Some(param) = single_param(&f.params) {
            if let Some(expr) = f.get_expression() {
                self.consider(&param, expr);
            } else if let Some(body) = f.body.as_function_body() {
                self.consider_statements(&param, &body.statements);
            }
        }
        walk::walk_arrow_function_expression(self, f);
    }

    fn visit_assignment_expression(&mut self, it: &oxc_ast::ast::AssignmentExpression<'a>) {
        // `__webpack_require__.p = "/static/"` (minified: `n.p="/"`).
        if let AssignmentTarget::StaticMemberExpression(m) = &it.left
            && m.property.name == "p"
            && let Expression::StringLiteral(s) = &it.right
        {
            self.public_paths.push(s.value.display().to_string());
        }
        walk::walk_assignment_expression(self, it);
    }

    fn visit_import_expression(&mut self, it: &oxc_ast::ast::ImportExpression<'a>) {
        if let Some(s) = super::string_value(&it.source)
            && !s.contains("${")
        {
            self.esm_specifiers.push(s);
        }
        walk::walk_import_expression(self, it);
    }

    fn visit_import_declaration(&mut self, it: &oxc_ast::ast::ImportDeclaration<'a>) {
        self.esm_specifiers
            .push(it.source.value.display().to_string());
    }

    fn visit_export_all_declaration(&mut self, it: &oxc_ast::ast::ExportAllDeclaration<'a>) {
        self.esm_specifiers
            .push(it.source.value.display().to_string());
    }

    fn visit_export_from_declaration(&mut self, it: &oxc_ast::ast::ExportFromDeclaration<'a>) {
        self.esm_specifiers
            .push(it.source.value.display().to_string());
    }

    fn visit_array_expression(&mut self, it: &oxc_ast::ast::ArrayExpression<'a>) {
        // A preload dependency list: every element a string, at least one JS.
        let strings: Option<Vec<String>> = it
            .elements
            .iter()
            .map(|e| match e {
                ArrayExpressionElement::StringLiteral(s) => Some(s.value.display().to_string()),
                _ => None,
            })
            .collect();
        if let Some(strings) = strings {
            let looks_like_deps = !strings.is_empty()
                && strings.iter().any(|s| is_js_path(s))
                && strings.iter().all(|s| is_js_path(s) || s.ends_with(".css"));
            if looks_like_deps {
                self.preload_deps
                    .extend(strings.into_iter().filter(|s| is_js_path(s)));
            }
        }
        walk::walk_array_expression(self, it);
    }
}

// ---------------------------------------------------------------------------
// Static scan + evaluator
// ---------------------------------------------------------------------------

/// Facts about an expression gathered before evaluation.
#[derive(Default)]
struct ExprInfo {
    uses_param: bool,
    has_js_literal: bool,
    /// Union of the keys of every `{…}[param]` table.
    keys: BTreeSet<String>,
}

impl ExprInfo {
    fn scan(&mut self, expr: &Expression<'_>, param: &str) {
        match expr.without_parentheses() {
            Expression::Identifier(id) if id.name == param => self.uses_param = true,
            Expression::StringLiteral(s) => {
                let v = s.value.display().to_string();
                if v.contains(".js") || v.contains(".mjs") {
                    self.has_js_literal = true;
                }
            }
            Expression::TemplateLiteral(t) => {
                for q in &t.quasis {
                    if q.value.raw.as_str().contains(".js") {
                        self.has_js_literal = true;
                    }
                }
                for e in &t.expressions {
                    self.scan(e, param);
                }
            }
            Expression::BinaryExpression(b) => {
                self.scan(&b.left, param);
                self.scan(&b.right, param);
            }
            Expression::LogicalExpression(l) => {
                self.scan(&l.left, param);
                self.scan(&l.right, param);
            }
            Expression::ConditionalExpression(c) => {
                self.scan(&c.test, param);
                self.scan(&c.consequent, param);
                self.scan(&c.alternate, param);
            }
            Expression::SequenceExpression(s) => {
                if let Some(last) = s.expressions.last() {
                    self.scan(last, param);
                }
            }
            Expression::ComputedMemberExpression(m) => {
                if let (Expression::ObjectExpression(obj), true) = (
                    m.object.without_parentheses(),
                    is_param(&m.expression, param),
                ) {
                    self.uses_param = true;
                    let table = object_table(obj);
                    // `{1:"page.js"}[id]`: the `.js` may live in the values.
                    if table.values().any(|v| v.contains(".js")) {
                        self.has_js_literal = true;
                    }
                    self.keys.extend(table.into_keys());
                } else {
                    self.scan(&m.object, param);
                }
            }
            _ => {}
        }
    }
}

fn is_param(e: &Expression<'_>, param: &str) -> bool {
    matches!(e.without_parentheses(), Expression::Identifier(id) if id.name == param)
}

/// The string table of an object literal: `{12:"a", "x":"b"}`.
fn object_table(obj: &ObjectExpression<'_>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(p) = prop else {
            continue;
        };
        let Some(key) = property_key(&p.key) else {
            continue;
        };
        let value = match &p.value {
            Expression::StringLiteral(s) => s.value.display().to_string(),
            Expression::NumericLiteral(n) => number_to_string(n.value),
            _ => continue,
        };
        map.insert(key, value);
    }
    map
}

fn property_key(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
        PropertyKey::StringLiteral(s) => Some(s.value.display().to_string()),
        PropertyKey::NumericLiteral(n) => Some(number_to_string(n.value)),
        _ => None,
    }
}

/// Format a JS number the way `String(n)` would for the integers and simple
/// decimals that appear as chunk ids.
fn number_to_string(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// Evaluates a chunk-name expression for one value of the parameter.
struct Evaluator<'k> {
    param: &'k str,
    key: &'k str,
}

impl Evaluator<'_> {
    fn eval(&self, expr: &Expression<'_>) -> Option<String> {
        match expr.without_parentheses() {
            Expression::StringLiteral(s) => Some(s.value.display().to_string()),
            Expression::NumericLiteral(n) => Some(number_to_string(n.value)),
            Expression::Identifier(id) if id.name == self.param => Some(self.key.to_string()),
            Expression::TemplateLiteral(t) => {
                let mut out = String::new();
                for (i, q) in t.quasis.iter().enumerate() {
                    out.push_str(&q.value.cooked.as_ref()?.display().to_string());
                    if let Some(e) = t.expressions.get(i) {
                        out.push_str(&self.eval(e)?);
                    }
                }
                Some(out)
            }
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
                Some(self.eval(&b.left)? + &self.eval(&b.right)?)
            }
            Expression::LogicalExpression(l) if l.operator == LogicalOperator::Or => {
                self.eval(&l.left).or_else(|| self.eval(&l.right))
            }
            Expression::ConditionalExpression(c) => match self.test(&c.test)? {
                true => self.eval(&c.consequent),
                false => self.eval(&c.alternate),
            },
            Expression::SequenceExpression(s) => self.eval(s.expressions.last()?),
            Expression::ComputedMemberExpression(m) => match m.object.without_parentheses() {
                Expression::ObjectExpression(obj) if is_param(&m.expression, self.param) => {
                    object_table(obj).remove(self.key)
                }
                _ => None,
            },
            // The public path is applied later in `resolve_webpack`.
            Expression::StaticMemberExpression(m) if m.property.name == "p" => Some(String::new()),
            _ => None,
        }
    }

    /// Evaluate `param === literal` style tests.
    fn test(&self, expr: &Expression<'_>) -> Option<bool> {
        let Expression::BinaryExpression(b) = expr.without_parentheses() else {
            return None;
        };
        let eq = match b.operator {
            BinaryOperator::StrictEquality | BinaryOperator::Equality => true,
            BinaryOperator::StrictInequality | BinaryOperator::Inequality => false,
            _ => return None,
        };
        let (l, r) = (self.eval(&b.left)?, self.eval(&b.right)?);
        Some((l == r) == eq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxc_allocator::Allocator;

    const LIMITS: Limits = Limits {
        bruteforce: 5,
        max_urls: 1000,
    };

    fn run(src: &str, script: &str) -> Discovery {
        let alloc = Allocator::default();
        let program = super::super::parse(&alloc, src).unwrap();
        discover(&program, &Url::parse(script).unwrap(), LIMITS)
    }

    fn strs(d: &Discovery) -> Vec<String> {
        d.urls.iter().map(|u| u.to_string()).collect()
    }

    #[test]
    fn webpack5_arrow_with_hash_table() {
        let d = run(
            r#"r.p="/"; r.u = e => "static/js/" + e + "." + {12:"a1b2",34:"c3d4"}[e] + ".chunk.js";"#,
            "https://app.test/static/js/main.js",
        );
        assert_eq!(
            strs(&d),
            vec![
                "https://app.test/static/js/12.a1b2.chunk.js",
                "https://app.test/static/js/34.c3d4.chunk.js"
            ]
        );
        assert!(!d.bruteforced);
    }

    #[test]
    fn webpack4_function_with_names_and_public_path() {
        let d = run(
            r#"n.p="/assets/";function a(e){return n.p+""+({5:"vendors"}[e]||e)+"."+{5:"9f8e",7:"aaaa"}[e]+".js"}"#,
            "https://app.test/x/main.js",
        );
        assert_eq!(
            strs(&d),
            vec![
                "https://app.test/assets/vendors.9f8e.js",
                "https://app.test/assets/7.aaaa.js"
            ]
        );
    }

    #[test]
    fn auto_public_path_uses_matching_prefix() {
        let d = run(
            r#"r.u = e => "static/js/" + e + "." + {1:"h"}[e] + ".chunk.js";"#,
            "https://app.test/sub/static/js/main.js",
        );
        assert_eq!(
            strs(&d),
            vec!["https://app.test/sub/static/js/1.h.chunk.js"]
        );
    }

    #[test]
    fn template_and_conditional() {
        let d = run(
            r#"const u = e => `chunks/${e === 1 ? "main" : e}.${{1:"x",2:"y"}[e]}.js`;"#,
            "https://app.test/chunks/runtime.js",
        );
        assert_eq!(
            strs(&d),
            vec![
                "https://app.test/chunks/main.x.js",
                "https://app.test/chunks/2.y.js"
            ]
        );
    }

    #[test]
    fn bruteforce_when_no_table() {
        let d = run(
            r#"r.u = e => "js/" + e + ".js";"#,
            "https://app.test/js/main.js",
        );
        assert!(d.bruteforced);
        assert_eq!(d.urls.len(), LIMITS.bruteforce as usize);
        assert_eq!(d.urls[0].as_str(), "https://app.test/js/0.js");
    }

    #[test]
    fn vite_imports_and_preload() {
        let d = run(
            r#"import a from "./vendor-abc.js";
               export * from "../shared-1.js";
               import react from "react";
               const p = () => __vitePreload(() => import("./Page-123.js"), ["assets/Page-123.js","assets/Page-123.css"]);
               import("https://cdn.test/x.js");"#,
            "https://app.test/assets/index-9.js",
        );
        let got = strs(&d);
        assert!(got.contains(&"https://app.test/assets/vendor-abc.js".to_string()));
        assert!(got.contains(&"https://app.test/shared-1.js".to_string()));
        assert!(got.contains(&"https://app.test/assets/Page-123.js".to_string()));
        assert!(got.contains(&"https://cdn.test/x.js".to_string()));
        assert!(!got.iter().any(|u| u.contains("react")), "{got:?}");
        // de-duplicated
        assert_eq!(got.len(), 4);
    }

    /// Codex M3 #1: filenames that live entirely in the table.
    #[test]
    fn table_only_filenames() {
        let d = run(
            r#"r.u = e => ({1:"page.abc.js",2:"vendor.def.js"})[e];"#,
            "https://app.test/js/main.js",
        );
        assert_eq!(
            strs(&d),
            vec![
                "https://app.test/js/page.abc.js",
                "https://app.test/js/vendor.def.js"
            ]
        );
    }

    /// Codex M3 #2: relative public paths are concatenated like webpack does.
    #[test]
    fn relative_public_path() {
        let d = run(
            r#"r.p = "../chunks/"; r.u = e => e + "." + {7:"h"}[e] + ".js";"#,
            "https://app.test/app/js/main.js",
        );
        assert_eq!(strs(&d), vec!["https://app.test/app/chunks/7.h.js"]);
    }

    /// Codex M2 #13: extensionless relative imports are followed; CSS isn't.
    #[test]
    fn extensionless_imports() {
        let d = run(
            r#"import("./bootstrap"); import "./styles.css"; import x from "../lib/util";"#,
            "https://app.test/a/b/main.js",
        );
        assert_eq!(
            strs(&d),
            vec![
                "https://app.test/a/b/bootstrap",
                "https://app.test/a/lib/util"
            ]
        );
    }

    #[test]
    fn non_chunk_functions_are_ignored() {
        let d = run(
            r#"function add(a){ return a + 1 } const f = x => "hello " + x;"#,
            "https://a.test/a.js",
        );
        assert!(d.urls.is_empty());
    }

    #[test]
    fn max_urls_is_enforced() {
        let alloc = Allocator::default();
        let program = super::super::parse(&alloc, r#"r.u = e => e + ".js";"#).unwrap();
        let d = discover(
            &program,
            &Url::parse("https://a.test/a.js").unwrap(),
            Limits {
                bruteforce: 100,
                max_urls: 3,
            },
        );
        assert_eq!(d.urls.len(), 3);
    }
}
