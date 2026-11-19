//! Security review (2nd pass) #2: every attacker-derived field printed by
//! the CLI goes through `clean(…)` / `Clean(…)`. This scans `src/main.rs`
//! so a new raw `println!` of a finding field fails CI.

#[test]
fn cli_prints_untrusted_fields_through_clean() {
    let src = include_str!("../src/main.rs");
    let fields = [
        "f.value",
        "f.category",
        "f.asset_url",
        "r.url",
        "r.path",
        "r.parent_url",
    ];
    let mut offenders = Vec::new();
    // Walk every println!/eprintln! invocation up to its closing `);`.
    for (start, _) in src.match_indices("println!(") {
        let end = src[start..].find(");").map_or(src.len(), |e| start + e);
        let call = &src[start..end];
        for field in fields {
            for (i, _) in call.match_indices(field) {
                let before = &call[..i];
                if !(before.ends_with("clean(&") || before.ends_with("Clean(&")) {
                    offenders.push(call.to_string());
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "unsanitized output:\n{}",
        offenders.join("\n---\n")
    );
}
