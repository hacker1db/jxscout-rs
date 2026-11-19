//! Framework-specific rules.

use oxc_ast::AstKind;
use oxc_ast::ast::{JSXAttributeName, PropertyKey};

use super::{Rule, RuleContext};

/// React `dangerouslySetInnerHTML`, both in JSX and in compiled
/// `createElement(…, {dangerouslySetInnerHTML: …})` form.
pub struct ReactRule;

impl Rule for ReactRule {
    fn id(&self) -> &'static str {
        "react"
    }
    fn description(&self) -> &'static str {
        "React dangerouslySetInnerHTML (JSX and compiled)"
    }
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
        const NAME: &str = "dangerouslySetInnerHTML";
        let span = match node {
            AstKind::JSXAttribute(a) => match &a.name {
                JSXAttributeName::Identifier(id) if id.name.as_str() == NAME => a.span,
                _ => return,
            },
            AstKind::ObjectProperty(p) => match &p.key {
                PropertyKey::StaticIdentifier(id) if id.name == NAME => p.span,
                PropertyKey::StringLiteral(s) if s.value.display().to_string() == NAME => p.span,
                _ => return,
            },
            _ => return,
        };
        cx.report(
            span,
            "Frameworks/React/dangerouslySetInnerHTML",
            cx.snippet(span),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::run;
    use super::*;

    #[test]
    fn jsx_and_compiled() {
        let f = run(
            ReactRule,
            r#"const a = <div dangerouslySetInnerHTML={{__html: x}} />;
               const b = React.createElement("div", {dangerouslySetInnerHTML: {__html: y}});"#,
        );
        assert_eq!(f.len(), 2, "{f:?}");
    }
}
