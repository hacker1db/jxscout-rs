//! The AST rule engine (SPEC R-80..R-83, upstream #16).
//!
//! A [`Rule`] looks at one AST node at a time and reports [`Finding`]s
//! through a [`RuleContext`]. The [`Registry`] holds the active rules, and
//! [`analyze`] walks a program once, offering every node to every rule.
//!
//! Adding a rule means: write a struct, `impl Rule for it`, and add it to
//! [`Registry::default`]. Nothing else in the pipeline changes. See
//! `CHALLENGES.md` for a guided exercise.
//!
//! Categories are `/`-separated paths that mirror the upstream analysis
//! tree (`docs/tree.md` upstream), e.g. `Client Behavior/Events/postMessage`.

mod client;
mod data;
mod frameworks;
mod secrets;

use std::collections::HashSet;

use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_ast::ast::{AssignmentTarget, Program};
use oxc_ast_visit::Visit;
use oxc_span::{GetSpan, Span};
use serde::Serialize;

use crate::js::{LineIndex, ParseFailure};

pub use client::{DomStateRule, EventsRule, NetworkRule, SinksRule};
pub use data::{GraphQlRule, RegexRule, StringsRule};
pub use frameworks::ReactRule;
pub use secrets::SecretsRule;

/// One thing a rule found.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Finding {
    /// Id of the rule that reported it.
    pub rule: &'static str,
    /// Category path, e.g. `Data/Paths/API`.
    pub category: String,
    /// The interesting value (a path, an event name, a code snippet, …).
    pub value: String,
    /// 1-based line in the analyzed (beautified) file.
    pub line: u32,
    /// 1-based byte column.
    pub column: u32,
}

/// A detection rule. Rules must be `Send + Sync` so one registry can be
/// shared by all pipeline workers.
pub trait Rule: Send + Sync {
    /// Short, stable, kebab-case id (used in the DB and `--rules` filters).
    fn id(&self) -> &'static str;
    /// One-line description for `jxscout-rs rules`.
    fn description(&self) -> &'static str;
    /// Inspect one node. Called for every node in the program, parents
    /// before children.
    fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>);
}

/// What a rule can see and do while checking a node.
pub struct RuleContext<'s> {
    source: &'s str,
    lines: &'s LineIndex,
    rule: &'static str,
    findings: &'s mut Vec<Finding>,
    assignment_targets: &'s HashSet<Span>,
}

impl RuleContext<'_> {
    /// Record a finding at `span`.
    pub fn report(&mut self, span: Span, category: impl Into<String>, value: impl Into<String>) {
        let (line, column) = self.lines.line_col(span.start);
        let mut value: String = value.into();
        if value.chars().count() > 300 {
            value = value.chars().take(300).collect::<String>() + "…";
        }
        self.findings.push(Finding {
            rule: self.rule,
            category: crate::text::category(&category.into()),
            value,
            line,
            column,
        });
    }

    /// The source text of a span, truncated to 200 characters.
    pub fn snippet(&self, span: Span) -> String {
        crate::js::snippet(self.source, span, 200)
    }

    /// Whether `span` is the left-hand side of an assignment. Lets rules
    /// tell `x.innerHTML = …` (write) from `y = x.innerHTML` (read).
    pub fn is_assignment_target(&self, span: Span) -> bool {
        self.assignment_targets.contains(&span)
    }
}

/// The set of active rules.
pub struct Registry {
    rules: Vec<Box<dyn Rule>>,
}

impl Default for Registry {
    /// Every built-in rule.
    fn default() -> Self {
        Self {
            rules: vec![
                Box::new(EventsRule),
                Box::new(SinksRule),
                Box::new(DomStateRule),
                Box::new(NetworkRule),
                Box::new(StringsRule),
                Box::new(RegexRule),
                Box::new(GraphQlRule),
                Box::new(SecretsRule::default()),
                Box::new(ReactRule),
            ],
        }
    }
}

impl Registry {
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn with(mut self, rule: impl Rule + 'static) -> Self {
        self.rules.push(Box::new(rule));
        self
    }

    /// Keep only the rules whose id is in `ids`.
    pub fn only(mut self, ids: &[String]) -> Self {
        self.rules.retain(|r| ids.iter().any(|id| id == r.id()));
        self
    }

    pub fn rules(&self) -> impl Iterator<Item = &dyn Rule> {
        self.rules.iter().map(|r| r.as_ref())
    }
}

/// Walks the AST and fans each node out to every rule.
struct Analyzer<'r> {
    registry: &'r Registry,
    source: &'r str,
    lines: LineIndex,
    findings: Vec<Finding>,
    assignment_targets: HashSet<Span>,
}

impl<'a> Visit<'a> for Analyzer<'_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        // Parents are entered before children, so the LHS span is known
        // before the LHS member expression itself is visited.
        if let AstKind::AssignmentExpression(a) = kind {
            if let AssignmentTarget::StaticMemberExpression(m) = &a.left {
                self.assignment_targets.insert(m.span);
            } else if let AssignmentTarget::ComputedMemberExpression(m) = &a.left {
                self.assignment_targets.insert(m.span);
            } else {
                self.assignment_targets.insert(a.left.span());
            }
        }
        for rule in &self.registry.rules {
            let mut cx = RuleContext {
                source: self.source,
                lines: &self.lines,
                rule: rule.id(),
                findings: &mut self.findings,
                assignment_targets: &self.assignment_targets,
            };
            rule.check(kind, &mut cx);
        }
    }
}

/// Run every rule in `registry` over an already-parsed program.
pub fn analyze(source: &str, program: &Program<'_>, registry: &Registry) -> Vec<Finding> {
    let mut a = Analyzer {
        registry,
        source,
        lines: LineIndex::new(source),
        findings: Vec::new(),
        assignment_targets: HashSet::new(),
    };
    a.visit_program(program);
    let mut findings = a.findings;
    findings.sort();
    findings.dedup();
    findings
}

/// Parse and analyze `source` in one go.
pub fn analyze_source(source: &str, registry: &Registry) -> Result<Vec<Finding>, ParseFailure> {
    let alloc = Allocator::default();
    let program = crate::js::parse(&alloc, source)?;
    Ok(analyze(source, &program, registry))
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;

    /// Run one rule and return `(category, value)` pairs.
    pub fn run(rule: impl Rule + 'static, src: &str) -> Vec<(String, String)> {
        let reg = Registry::empty().with(rule);
        analyze_source(src, &reg)
            .unwrap()
            .into_iter()
            .map(|f| (f.category, f.value))
            .collect()
    }

    pub fn has(found: &[(String, String)], category: &str, value: &str) -> bool {
        found.iter().any(|(c, v)| c == category && v == value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountCalls;
    impl Rule for CountCalls {
        fn id(&self) -> &'static str {
            "count-calls"
        }
        fn description(&self) -> &'static str {
            "test rule"
        }
        fn check(&self, node: AstKind<'_>, cx: &mut RuleContext<'_>) {
            if let AstKind::CallExpression(c) = node {
                cx.report(c.span, "Test/Call", cx.snippet(c.span));
            }
        }
    }

    #[test]
    fn custom_rule_plugs_in() {
        let reg = Registry::empty().with(CountCalls);
        let f = analyze_source("a();\nb(1);", &reg).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!((f[1].line, f[1].column), (2, 1));
        assert_eq!(f[1].value, "b(1)");
    }

    #[test]
    fn default_registry_ids_are_unique() {
        let reg = Registry::default();
        let mut ids: Vec<_> = reg.rules().map(|r| r.id()).collect();
        let n = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), n);
        assert_eq!(
            Registry::default()
                .only(&["secrets".into()])
                .rules()
                .count(),
            1
        );
    }
}
