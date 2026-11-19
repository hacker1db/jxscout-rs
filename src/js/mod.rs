//! JavaScript handling: parsing, beautifying, and AST helpers shared by the
//! chunk finder and the rule engine.
//!
//! All parsing uses [oxc](https://oxc.rs), a pure-Rust JS parser, which is
//! what lets this tool drop the upstream Bun/Node/Prettier dependency
//! (SPEC R-02, upstream #17).
//!
//! ## Lifetimes, briefly
//!
//! oxc allocates the whole AST in an arena ([`Allocator`]). Every AST node
//! borrows from that arena *and* from the source text, which is why you see
//! `Program<'a>` everywhere: `'a` is "as long as the arena and the source
//! live". Functions here take `&'a Allocator` and `&'a str` and hand back
//! things tied to `'a`; once the allocator is dropped, the AST is gone.

pub mod chunks;
pub mod html;
pub mod sourcemap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Program};
use oxc_codegen::Codegen;
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};

/// A parse failure, with oxc's first diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ParseFailure {
    pub message: String,
}

/// Parse `source` as an ES module or script (auto-detected), falling back
/// to JSX. Returns an error only if the parser could not recover at all;
/// recoverable syntax errors still yield a usable AST (R-42, R-43).
pub fn parse<'a>(alloc: &'a Allocator, source: &'a str) -> Result<Program<'a>, ParseFailure> {
    let mut first_error = None;
    for source_type in [SourceType::unambiguous(), SourceType::jsx()] {
        let ret = Parser::new(alloc, source, source_type).parse();
        if !ret.fatal_error {
            return Ok(ret.program);
        }
        if first_error.is_none() {
            first_error = Some(
                ret.diagnostics
                    .first()
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "unknown parse error".into()),
            );
        }
    }
    Err(ParseFailure {
        message: first_error.unwrap_or_default(),
    })
}

/// Pretty-print JavaScript by parsing it and re-emitting it with oxc's code
/// generator (no Prettier needed).
pub fn beautify(source: &str) -> Result<String, ParseFailure> {
    let alloc = Allocator::default();
    let program = parse(&alloc, source)?;
    Ok(Codegen::new().build(&program).code)
}

/// Maps byte offsets to 1-based `(line, column)` pairs.
#[derive(Debug, Clone)]
pub struct LineIndex {
    /// Byte offset of the start of every line.
    starts: Vec<u32>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            source
                .bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| i as u32 + 1),
        );
        Self { starts }
    }

    pub fn line_col(&self, offset: u32) -> (u32, u32) {
        // `partition_point` is a binary search for the first line start
        // greater than `offset`; the line we want is the one before it.
        let line = self.starts.partition_point(|&s| s <= offset);
        let start = self.starts[line - 1];
        (line as u32, offset - start + 1)
    }
}

/// Source text of a span, shortened to at most `max` characters.
pub fn snippet(source: &str, span: Span, max: usize) -> String {
    let text = source
        .get(span.start as usize..span.end as usize)
        .unwrap_or_default();
    let mut out: String = text.chars().take(max).collect();
    if text.chars().count() > max {
        out.push('…');
    }
    out
}

/// Dotted name of a member chain: `window.location.href`, `a["b"].c`,
/// `this.x`. Returns `None` for anything not made of identifiers/literal keys.
pub fn member_path(expr: &Expression<'_>) -> Option<String> {
    match expr.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::ThisExpression(_) => Some("this".into()),
        // `document.getElementById("x").innerHTML` → `document.getElementById().innerHTML`
        Expression::CallExpression(c) => Some(format!("{}()", member_path(&c.callee)?)),
        Expression::StaticMemberExpression(m) => {
            Some(format!("{}.{}", member_path(&m.object)?, m.property.name))
        }
        Expression::ComputedMemberExpression(m) => match &m.expression {
            Expression::StringLiteral(s) => {
                Some(format!("{}.{}", member_path(&m.object)?, s.value.display()))
            }
            _ => None,
        },
        Expression::ChainExpression(c) => {
            c.expression.as_member_expression().and_then(|m| match m {
                oxc_ast::ast::MemberExpression::StaticMemberExpression(s) => {
                    Some(format!("{}.{}", member_path(&s.object)?, s.property.name))
                }
                _ => None,
            })
        }
        _ => None,
    }
}

/// The last component of a member path: `"a.b.c"` → `"c"`.
pub fn last_segment(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

/// The value of a string-ish expression. Templates with substitutions are
/// rendered with `${…}` placeholders, which is what you want when reading
/// paths like `` `/api/users/${id}` ``.
pub fn string_value(expr: &Expression<'_>) -> Option<String> {
    match expr.without_parentheses() {
        Expression::StringLiteral(s) => Some(s.value.display().to_string()),
        Expression::TemplateLiteral(t) => {
            let mut out = String::new();
            for (i, q) in t.quasis.iter().enumerate() {
                match &q.value.cooked {
                    Some(c) => out.push_str(&c.display().to_string()),
                    None => out.push_str(q.value.raw.as_str()),
                }
                if i < t.expressions.len() {
                    out.push_str("${…}");
                }
            }
            Some(out)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beautify_reformats_minified_code() {
        let out = beautify("function a(b){return b+1}var c=a(2);").unwrap();
        assert!(out.lines().count() >= 3, "{out}");
        assert!(out.contains("return b + 1"));
    }

    /// Regression for upstream #19 ("Unexpected token"): garbage input is an
    /// error value, not a panic or a pipeline abort.
    #[test]
    fn parse_errors_are_values() {
        let err = beautify("<html><body>not js").unwrap_err();
        assert!(!err.message.is_empty());
        assert!(beautify("function (").is_err());
    }

    #[test]
    fn modules_and_jsx_parse() {
        assert!(beautify("import x from './a.js'; export default x;").is_ok());
        assert!(beautify("const el = <div dangerouslySetInnerHTML={{__html: x}} />;").is_ok());
    }

    #[test]
    fn line_index() {
        let idx = LineIndex::new("ab\ncd\n\nef");
        assert_eq!(idx.line_col(0), (1, 1));
        assert_eq!(idx.line_col(1), (1, 2));
        assert_eq!(idx.line_col(3), (2, 1));
        assert_eq!(idx.line_col(7), (4, 1));
    }

    #[test]
    fn member_paths() {
        let alloc = Allocator::default();
        let src = "window.location.href; a['b'].c; (x).y; foo?.bar; document.getElementById('o').innerHTML;";
        let program = parse(&alloc, src).unwrap();
        let paths: Vec<_> = program
            .body
            .iter()
            .filter_map(|s| match s {
                oxc_ast::ast::Statement::ExpressionStatement(e) => member_path(&e.expression),
                _ => None,
            })
            .collect();
        assert_eq!(
            paths,
            vec![
                "window.location.href",
                "a.b.c",
                "x.y",
                "foo.bar",
                "document.getElementById().innerHTML"
            ]
        );
    }
}
