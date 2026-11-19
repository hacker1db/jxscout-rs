//! "Client Behavior" rules: events, dangerous sinks, DOM state, network.

use oxc_ast::AstKind;
use oxc_ast::ast::{Argument, AssignmentTarget, Expression, ObjectPropertyKind, PropertyKey};
use oxc_span::GetSpan;

use super::{Rule, RuleContext};
use crate::js::{last_segment, member_path, string_value};

fn arg_expr<'b, 'a>(args: &'b [Argument<'a>], i: usize) -> Option<&'b Expression<'a>> {
    args.get(i).and_then(|a| a.as_expression())
}

/// Dotted path of an assignment target, e.g. `el.innerHTML`.
fn target_path(t: &AssignmentTarget<'_>) -> Option<String> {
    match t {
        AssignmentTarget::AssignmentTargetIdentifier(id) => Some(id.name.to_string()),
        AssignmentTarget::StaticMemberExpression(m) => {
            // Unknown objects (`arr[i].innerHTML = …`) still count as sinks.
            let object = member_path(&m.object).unwrap_or_else(|| "(expr)".into());
            Some(format!("{object}.{}", m.property.name))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------

/// `addEventListener`, `onmessage`, `onhashchange`, `postMessage`.
pub struct EventsRule;

impl Rule for EventsRule {
    fn id(&self) -> &'static str {
        "events"
    }
    fn description(&self) -> &'static str {
        "Event listeners and cross-window messaging (addEventListener, onmessage, postMessage)"
    }
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
        match node {
            AstKind::CallExpression(call) => {
                let Some(path) = member_path(&call.callee) else {
                    return;
                };
                match last_segment(&path) {
                    "addEventListener" => {
                        let event = arg_expr(&call.arguments, 0)
                            .and_then(string_value)
                            .unwrap_or_else(|| "(dynamic)".into());
                        cx.report(call.span, "Client Behavior/Events/addEventListener", event);
                    }
                    "postMessage" => {
                        cx.report(
                            call.span,
                            "Client Behavior/Events/postMessage",
                            cx.snippet(call.span),
                        );
                    }
                    _ => {}
                }
            }
            AstKind::AssignmentExpression(a) => {
                let Some(path) = target_path(&a.left) else {
                    return;
                };
                let event = last_segment(&path);
                if matches!(event, "onmessage" | "onhashchange") {
                    cx.report(
                        a.span,
                        format!("Client Behavior/Events/{event}"),
                        cx.snippet(a.right.span()),
                    );
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------

/// `eval`, `Function`, string timers, `document.write`, `innerHTML`,
/// `insertAdjacentHTML`, `window.open`.
pub struct SinksRule;

impl Rule for SinksRule {
    fn id(&self) -> &'static str {
        "sinks"
    }
    fn description(&self) -> &'static str {
        "Dangerous DOM/JS sinks (eval, Function, innerHTML, document.write, window.open)"
    }
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
        match node {
            AstKind::CallExpression(call) => {
                let Some(path) = member_path(&call.callee) else {
                    return;
                };
                let category = match path.as_str() {
                    "eval" | "window.eval" | "Function" | "window.Function" => {
                        "Client Behavior/eval"
                    }
                    "setTimeout" | "setInterval" | "window.setTimeout" | "window.setInterval" => {
                        // Only string arguments are code; functions are fine.
                        let is_string = arg_expr(&call.arguments, 0).is_some_and(|e| {
                            matches!(
                                e,
                                Expression::StringLiteral(_) | Expression::TemplateLiteral(_)
                            )
                        });
                        if !is_string {
                            return;
                        }
                        "Client Behavior/eval"
                    }
                    "document.write" | "document.writeln" | "window.document.write" => {
                        "Client Behavior/document.write"
                    }
                    "window.open" => "Client Behavior/window.open",
                    p if last_segment(p) == "insertAdjacentHTML" => "Client Behavior/innerHTML",
                    _ => return,
                };
                cx.report(call.span, category, cx.snippet(call.span));
            }
            AstKind::NewExpression(n) => {
                if member_path(&n.callee).as_deref() == Some("Function") {
                    cx.report(n.span, "Client Behavior/eval", cx.snippet(n.span));
                }
            }
            AstKind::AssignmentExpression(a) => {
                let Some(path) = target_path(&a.left) else {
                    return;
                };
                if matches!(last_segment(&path), "innerHTML" | "outerHTML") {
                    cx.report(a.span, "Client Behavior/innerHTML", cx.snippet(a.span));
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------

/// Reads and writes of `location`, `document.domain`, `window.name`,
/// `document.cookie`, and Web Storage.
pub struct DomStateRule;

impl DomStateRule {
    fn rw(cx: &RuleContext<'_>, span: oxc_span::Span) -> &'static str {
        if cx.is_assignment_target(span) {
            "Assignment"
        } else {
            "Read"
        }
    }
}

impl Rule for DomStateRule {
    fn id(&self) -> &'static str {
        "dom-state"
    }
    fn description(&self) -> &'static str {
        "location, document.domain, window.name, cookies, localStorage/sessionStorage"
    }
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
        match node {
            AstKind::StaticMemberExpression(m) => {
                let Some(object) = member_path(&m.object) else {
                    return;
                };
                let prop = m.property.name.as_str();
                let full = format!("{object}.{prop}");
                let rw = Self::rw(cx, m.span);
                let obj_last = last_segment(&object);

                if full.ends_with("document.domain") {
                    cx.report(
                        m.span,
                        format!("Client Behavior/document.domain/{rw}"),
                        full,
                    );
                } else if full == "window.name" || full == "self.name" {
                    cx.report(m.span, format!("Client Behavior/window.name/{rw}"), full);
                } else if full.ends_with("document.cookie") {
                    cx.report(m.span, format!("Client Behavior/Storage/Cookie/{rw}"), full);
                } else if obj_last == "location"
                    && matches!(
                        object.as_str(),
                        "location"
                            | "window.location"
                            | "document.location"
                            | "self.location"
                            | "top.location"
                    )
                {
                    cx.report(
                        m.span,
                        format!("Client Behavior/Location/{rw}/{prop}"),
                        full,
                    );
                } else if matches!(obj_last, "localStorage" | "sessionStorage")
                    && !matches!(prop, "getItem" | "setItem" | "removeItem")
                {
                    cx.report(
                        m.span,
                        format!("Client Behavior/Storage/{obj_last}/{prop}"),
                        full,
                    );
                }
            }
            AstKind::CallExpression(call) => {
                let Some(path) = member_path(&call.callee) else {
                    return;
                };
                let mut parts = path.rsplitn(2, '.');
                let (method, object) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                let storage = last_segment(object);
                if matches!(storage, "localStorage" | "sessionStorage")
                    && matches!(method, "getItem" | "setItem" | "removeItem")
                {
                    let key = arg_expr(&call.arguments, 0)
                        .and_then(string_value)
                        .unwrap_or_else(|| "(dynamic)".into());
                    cx.report(
                        call.span,
                        format!("Client Behavior/Storage/{storage}/{method}"),
                        key,
                    );
                }
            }
            AstKind::AssignmentExpression(a) => {
                // Bare `location = "…"`.
                if let AssignmentTarget::AssignmentTargetIdentifier(id) = &a.left
                    && id.name == "location"
                {
                    cx.report(
                        a.span,
                        "Client Behavior/Location/Assignment/(self)",
                        cx.snippet(a.span),
                    );
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------

const HTTP_METHODS: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

/// `fetch`, XHR, axios/jQuery and other REST-looking clients,
/// `URLSearchParams`, `WebSocket`.
pub struct NetworkRule;

impl NetworkRule {
    /// `Object Schemas/Fetch Options` + `Data/Headers` from `fetch(url, {…})`.
    fn fetch_options(obj: &oxc_ast::ast::ObjectExpression<'_>, cx: &mut RuleContext<'_>) {
        let mut keys = Vec::new();
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(p) = prop else {
                continue;
            };
            let Some(key) = key_name(&p.key) else {
                continue;
            };
            if key == "method"
                && let Some(m) = string_value(&p.value)
            {
                keys.push(format!("method={m}"));
                continue;
            }
            if key == "headers"
                && let Expression::ObjectExpression(h) = &p.value
            {
                for hp in &h.properties {
                    if let ObjectPropertyKind::ObjectProperty(hp) = hp
                        && let Some(name) = key_name(&hp.key)
                    {
                        cx.report(hp.span, "Data/Headers", name);
                    }
                }
            }
            keys.push(key);
        }
        cx.report(obj.span, "Object Schemas/Fetch Options", keys.join(", "));
    }
}

fn key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
        PropertyKey::StringLiteral(s) => Some(s.value.display().to_string()),
        _ => None,
    }
}

impl Rule for NetworkRule {
    fn id(&self) -> &'static str {
        "network"
    }
    fn description(&self) -> &'static str {
        "HTTP clients: fetch, XMLHttpRequest, axios/jQuery/REST-like calls, URLSearchParams, WebSocket"
    }
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
        match node {
            AstKind::CallExpression(call) => {
                let Some(path) = member_path(&call.callee) else {
                    return;
                };
                let url_arg = || {
                    arg_expr(&call.arguments, 0)
                        .and_then(string_value)
                        .unwrap_or_else(|| cx.snippet(call.span))
                };
                if matches!(
                    path.as_str(),
                    "fetch" | "window.fetch" | "self.fetch" | "globalThis.fetch"
                ) {
                    cx.report(call.span, "Client Behavior/fetch", url_arg());
                    if let Some(Expression::ObjectExpression(obj)) = arg_expr(&call.arguments, 1) {
                        Self::fetch_options(obj, cx);
                    }
                    return;
                }
                let method = last_segment(&path).to_ascii_lowercase();
                // xhr.open("POST", "/api/x")
                if method == "open" && call.arguments.len() >= 2 {
                    let verb = arg_expr(&call.arguments, 0).and_then(string_value);
                    if let Some(verb) =
                        verb.filter(|v| HTTP_METHODS.contains(&v.to_ascii_lowercase().as_str()))
                    {
                        let target = arg_expr(&call.arguments, 1)
                            .and_then(string_value)
                            .unwrap_or_else(|| cx.snippet(call.span));
                        cx.report(
                            call.span,
                            format!(
                                "Client Behavior/Possible Rest Client/{}",
                                verb.to_ascii_uppercase()
                            ),
                            target,
                        );
                    }
                    return;
                }
                // $.ajax({url, type}) / jQuery.ajax
                if matches!(path.as_str(), "$.ajax" | "jQuery.ajax") {
                    cx.report(
                        call.span,
                        "Client Behavior/Possible Rest Client/AJAX",
                        cx.snippet(call.span),
                    );
                    return;
                }
                // axios.get("/x"), api.post("/users"), $.get("/y") …
                if HTTP_METHODS.contains(&method.as_str()) {
                    let first = arg_expr(&call.arguments, 0).and_then(string_value);
                    let is_known_client = path.starts_with("axios.")
                        || path.starts_with("$.")
                        || path.starts_with("jQuery.");
                    if let Some(target) = first
                        && (is_known_client
                            || target.starts_with('/')
                            || target.starts_with("http"))
                    {
                        cx.report(
                            call.span,
                            format!(
                                "Client Behavior/Possible Rest Client/{}",
                                method.to_ascii_uppercase()
                            ),
                            target,
                        );
                    }
                }
            }
            AstKind::NewExpression(n) => {
                let Some(path) = member_path(&n.callee) else {
                    return;
                };
                let category = match path.as_str() {
                    "URLSearchParams" | "window.URLSearchParams" => {
                        "Client Behavior/URLSearchParams"
                    }
                    "WebSocket" | "window.WebSocket" => "Client Behavior/WebSocket",
                    _ => return,
                };
                cx.report(n.span, category, cx.snippet(n.span));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{has, run};
    use super::*;

    #[test]
    fn events() {
        let f = run(
            EventsRule,
            r#"window.addEventListener("message", h); w.postMessage(data, "*"); window.onhashchange = go;"#,
        );
        assert!(has(
            &f,
            "Client Behavior/Events/addEventListener",
            "message"
        ));
        assert!(has(
            &f,
            "Client Behavior/Events/postMessage",
            r#"w.postMessage(data, "*")"#
        ));
        assert!(has(&f, "Client Behavior/Events/onhashchange", "go"));
    }

    #[test]
    fn sinks() {
        let f = run(
            SinksRule,
            r#"eval(x); new Function("a", b); setTimeout("alert(1)", 1); setTimeout(fn, 1);
               el.innerHTML = user; document.write(s); window.open(u); el.insertAdjacentHTML("beforeend", h);"#,
        );
        let cats: Vec<&str> = f.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(
            cats.iter()
                .filter(|c| **c == "Client Behavior/eval")
                .count(),
            3
        );
        assert!(cats.contains(&"Client Behavior/innerHTML"));
        assert!(cats.contains(&"Client Behavior/document.write"));
        assert!(cats.contains(&"Client Behavior/window.open"));
        assert_eq!(
            cats.iter()
                .filter(|c| **c == "Client Behavior/innerHTML")
                .count(),
            2
        );
    }

    #[test]
    fn dom_state_read_vs_write() {
        let f = run(
            DomStateRule,
            r#"location.href = u; const h = window.location.hash; document.domain = "a.com";
               const c = document.cookie; localStorage.setItem("token", t); sessionStorage.debug;"#,
        );
        assert!(has(
            &f,
            "Client Behavior/Location/Assignment/href",
            "location.href"
        ));
        assert!(has(
            &f,
            "Client Behavior/Location/Read/hash",
            "window.location.hash"
        ));
        assert!(has(
            &f,
            "Client Behavior/document.domain/Assignment",
            "document.domain"
        ));
        assert!(has(
            &f,
            "Client Behavior/Storage/Cookie/Read",
            "document.cookie"
        ));
        assert!(has(
            &f,
            "Client Behavior/Storage/localStorage/setItem",
            "token"
        ));
        assert!(has(
            &f,
            "Client Behavior/Storage/sessionStorage/debug",
            "sessionStorage.debug"
        ));
    }

    #[test]
    fn network() {
        let f = run(
            NetworkRule,
            r#"fetch("/api/v1/users", {method: "POST", headers: {"X-CSRF": t}, body: b});
               xhr.open("PUT", "/api/items/1"); axios.get("/api/me"); api.delete(`/users/${id}`);
               new URLSearchParams(location.search); map.get(key);"#,
        );
        assert!(has(&f, "Client Behavior/fetch", "/api/v1/users"));
        assert!(has(
            &f,
            "Object Schemas/Fetch Options",
            "method=POST, headers, body"
        ));
        assert!(has(&f, "Data/Headers", "X-CSRF"));
        assert!(has(
            &f,
            "Client Behavior/Possible Rest Client/PUT",
            "/api/items/1"
        ));
        assert!(has(
            &f,
            "Client Behavior/Possible Rest Client/GET",
            "/api/me"
        ));
        assert!(has(
            &f,
            "Client Behavior/Possible Rest Client/DELETE",
            "/users/${…}"
        ));
        assert!(
            f.iter()
                .any(|(c, _)| c == "Client Behavior/URLSearchParams")
        );
        // `map.get(key)` is not a REST call
        assert_eq!(f.iter().filter(|(c, _)| c.ends_with("/GET")).count(), 1);
    }
}
