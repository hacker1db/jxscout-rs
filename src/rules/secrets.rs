//! Hard-coded secrets and API keys.
//!
//! Two techniques:
//! 1. well-known token formats matched by regex anywhere in a string;
//! 2. "secret-looking" names (`apiKey`, `client_secret`, …) assigned a
//!    string value, which catches custom formats.
//!
//! Test fixtures use obviously fake values (see `.gitguardian.yaml`).

use std::sync::LazyLock;

use oxc_ast::AstKind;
use oxc_ast::ast::{BindingPattern, Expression, PropertyKey};
use oxc_span::Span;
use regex::Regex;

use super::data::string_like;
use super::{Rule, RuleContext};

/// `(type, regex)` pairs for known token formats.
static PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("aws-access-key-id", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        ("slack-token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
        (
            "slack-webhook",
            r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+",
        ),
        ("stripe-secret-key", r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
        ("stripe-publishable-key", r"\bpk_live_[0-9A-Za-z]{20,}\b"),
        (
            "jwt",
            r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        ),
        (
            "private-key",
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY",
        ),
        (
            "sendgrid-key",
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
        ),
        ("twilio-key", r"\bSK[0-9a-fA-F]{32}\b"),
        ("mailgun-key", r"\bkey-[0-9a-zA-Z]{32}\b"),
        ("firebase-url", r"https://[a-z0-9\-]+\.firebaseio\.com"),
    ]
    .into_iter()
    .map(|(name, re)| (name, Regex::new(re).expect("secret regex compiles")))
    .collect()
});

static SECRET_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(api[_\-]?key|apikey|secret|token|passw(or)?d|client[_\-]?secret|access[_\-]?key|auth[_\-]?key|private[_\-]?key)")
        .unwrap()
});

pub struct SecretsRule {
    /// Minimum length of a value assigned to a secret-looking name.
    min_assigned_len: usize,
}

impl Default for SecretsRule {
    fn default() -> Self {
        Self {
            min_assigned_len: 8,
        }
    }
}

impl SecretsRule {
    fn check_assignment(
        &self,
        span: Span,
        name: &str,
        value: &Expression<'_>,
        cx: &mut RuleContext<'_>,
    ) {
        let Expression::StringLiteral(s) = value else {
            return;
        };
        let v = s.value.display().to_string();
        let plausible = v.len() >= self.min_assigned_len
            && v.len() <= 200
            && !v.contains(char::is_whitespace)
            // Skip obvious non-secrets like `token: "Bearer"` or a path.
            && !v.starts_with('/')
            && v.chars().any(|c| c.is_ascii_digit());
        if plausible && SECRET_NAME_RE.is_match(name) {
            cx.report(
                span,
                "Data/Secrets/generic-assignment",
                format!("{name}={v}"),
            );
        }
    }
}

impl Rule for SecretsRule {
    fn id(&self) -> &'static str {
        "secrets"
    }
    fn description(&self) -> &'static str {
        "Hard-coded API keys, tokens, private keys, and secret-looking assignments"
    }
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
        if let Some((span, text)) = string_like(node) {
            for (name, re) in PATTERNS.iter() {
                for m in re.find_iter(&text) {
                    cx.report(span, format!("Data/Secrets/{name}"), m.as_str());
                }
            }
            return;
        }
        match node {
            AstKind::ObjectProperty(p) => {
                let name = match &p.key {
                    PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                    PropertyKey::StringLiteral(s) => s.value.display().to_string(),
                    _ => return,
                };
                self.check_assignment(p.span, &name, &p.value, cx);
            }
            AstKind::VariableDeclarator(d) => {
                if let (BindingPattern::BindingIdentifier(id), Some(init)) = (&d.id, &d.init) {
                    self.check_assignment(d.span, &id.name, init, cx);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{has, run};
    use super::*;

    // All values below are fake and documented example values.
    #[test]
    fn known_formats() {
        let f = run(
            SecretsRule::default(),
            r#"const aws = "AKIAIOSFODNN7EXAMPLE";
               const g = "AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE123";
               const k = "-----BEGIN RSA PRIVATE KEY-----\nFAKE";"#,
        );
        assert!(has(
            &f,
            "Data/Secrets/aws-access-key-id",
            "AKIAIOSFODNN7EXAMPLE"
        ));
        assert!(has(
            &f,
            "Data/Secrets/google-api-key",
            "AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE123"
        ));
        assert!(f.iter().any(|(c, _)| c == "Data/Secrets/private-key"));
    }

    #[test]
    fn secret_looking_assignments() {
        let f = run(
            SecretsRule::default(),
            r#"const config = { apiKey: "fake-0000-test-key", title: "hello123456" };
               var client_secret = "not-a-real-secret-42"; const token = "Bearer";"#,
        );
        assert!(has(
            &f,
            "Data/Secrets/generic-assignment",
            "apiKey=fake-0000-test-key"
        ));
        assert!(has(
            &f,
            "Data/Secrets/generic-assignment",
            "client_secret=not-a-real-secret-42"
        ));
        assert_eq!(f.len(), 2, "{f:?}");
    }
}
