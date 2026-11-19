//! The SQLite index of assets, page→script relations, and findings (R-35).
//!
//! `rusqlite::Connection` is `Send` but not `Sync`, so it lives behind a
//! `std::sync::Mutex`. Every query here is tiny, so holding a blocking mutex
//! for a few microseconds inside async code is fine; if queries ever become
//! slow they should move to `tokio::task::spawn_blocking`.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::events::AssetKind;
use crate::rules::Finding;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS assets (
    url        TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    path       TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    size       INTEGER NOT NULL,
    origin     TEXT NOT NULL,
    parent_url TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS relations (
    page_url   TEXT NOT NULL,
    script_url TEXT NOT NULL,
    PRIMARY KEY (page_url, script_url)
);
CREATE TABLE IF NOT EXISTS findings (
    asset_url TEXT NOT NULL,
    rule_id   TEXT NOT NULL,
    category  TEXT NOT NULL,
    value     TEXT NOT NULL,
    line      INTEGER NOT NULL,
    col       INTEGER NOT NULL,
    UNIQUE (asset_url, rule_id, category, value, line, col)
);
CREATE INDEX IF NOT EXISTS findings_by_asset ON findings(asset_url);
CREATE TABLE IF NOT EXISTS sourcemaps (
    js_url  TEXT PRIMARY KEY,
    map_url TEXT NOT NULL,
    sources INTEGER NOT NULL
);
"#;

/// A row of the `assets` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssetRow {
    pub url: String,
    pub kind: AssetKind,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub origin: String,
    pub parent_url: Option<String>,
}

/// A stored finding joined with its asset URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingRow {
    pub asset_url: String,
    pub rule_id: String,
    pub category: String,
    pub value: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug)]
pub struct Db {
    conn: Mutex<Connection>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        // WAL lets the CLI read while a `serve` process writes.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned lock only means another thread panicked mid-query; the
        // connection itself is still usable.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Hash of the stored content for `url`, if known. Used to skip
    /// re-processing unchanged files after a restart (R-35).
    pub fn asset_hash(&self, url: &str) -> rusqlite::Result<Option<String>> {
        self.conn()
            .query_row("SELECT sha256 FROM assets WHERE url = ?1", [url], |r| {
                r.get(0)
            })
            .optional()
    }

    pub fn upsert_asset(&self, row: &AssetRow) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO assets (url, kind, path, sha256, size, origin, parent_url, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(url) DO UPDATE SET kind=excluded.kind, path=excluded.path,
                sha256=excluded.sha256, size=excluded.size, origin=excluded.origin,
                parent_url=COALESCE(excluded.parent_url, assets.parent_url),
                updated_at=excluded.updated_at",
            params![
                row.url,
                row.kind.as_str(),
                row.path,
                row.sha256,
                row.size as i64,
                row.origin,
                row.parent_url,
                now()
            ],
        )?;
        Ok(())
    }

    /// Overwrite the stored content hash (used to store the hash of the
    /// original text when the saved file is the beautified version).
    pub fn upsert_asset_hash(&self, url: &str, sha256: &str) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE assets SET sha256 = ?2 WHERE url = ?1",
            [url, sha256],
        )?;
        Ok(())
    }

    pub fn add_relation(&self, page_url: &str, script_url: &str) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT OR IGNORE INTO relations (page_url, script_url) VALUES (?1, ?2)",
            [page_url, script_url],
        )?;
        Ok(())
    }

    /// Replace all findings of `asset_url` with `findings`.
    pub fn replace_findings(&self, asset_url: &str, findings: &[Finding]) -> rusqlite::Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM findings WHERE asset_url = ?1", [asset_url])?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO findings (asset_url, rule_id, category, value, line, col)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for f in findings {
                stmt.execute(params![
                    asset_url, f.rule, f.category, f.value, f.line, f.column
                ])?;
            }
        }
        tx.commit()
    }

    pub fn record_sourcemap(
        &self,
        js_url: &str,
        map_url: &str,
        sources: usize,
    ) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO sourcemaps (js_url, map_url, sources) VALUES (?1, ?2, ?3)
             ON CONFLICT(js_url) DO UPDATE SET map_url=excluded.map_url, sources=excluded.sources",
            params![js_url, map_url, sources as i64],
        )?;
        Ok(())
    }

    /// Assets whose URL contains `search` (all when `None`), newest first.
    pub fn assets(
        &self,
        search: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> rusqlite::Result<Vec<AssetRow>> {
        let pattern = format!("%{}%", search.unwrap_or_default());
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT url, kind, path, sha256, size, origin, parent_url FROM assets
             WHERE url LIKE ?1 ORDER BY updated_at DESC, url LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64, offset as i64], row_to_asset)?;
        rows.collect()
    }

    /// Like [`assets`](Self::assets) with each asset's finding count, in
    /// one query (the TUI loads thousands of rows at once).
    pub fn assets_with_counts(&self, limit: usize) -> rusqlite::Result<Vec<(AssetRow, usize)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT a.url, a.kind, a.path, a.sha256, a.size, a.origin, a.parent_url,
                    (SELECT COUNT(*) FROM findings f WHERE f.asset_url = a.url)
             FROM assets a ORDER BY a.updated_at DESC, a.url LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |r| {
            Ok((row_to_asset(r)?, r.get::<_, i64>(7)? as usize))
        })?;
        rows.collect()
    }

    /// Scripts loaded by an HTML page (`loads` command).
    pub fn scripts_of(&self, page_url: &str) -> rusqlite::Result<Vec<String>> {
        self.strings(
            "SELECT script_url FROM relations WHERE page_url = ?1 ORDER BY script_url",
            page_url,
        )
    }

    /// Pages that loaded a script (`loaded` command).
    pub fn pages_of(&self, script_url: &str) -> rusqlite::Result<Vec<String>> {
        self.strings(
            "SELECT page_url FROM relations WHERE script_url = ?1 ORDER BY page_url",
            script_url,
        )
    }

    fn strings(&self, sql: &str, arg: &str) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([arg], |r| r.get(0))?;
        rows.collect()
    }

    /// Findings, optionally filtered by asset URL and/or category prefix.
    pub fn findings(
        &self,
        asset_url: Option<&str>,
        category_prefix: Option<&str>,
    ) -> rusqlite::Result<Vec<FindingRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT asset_url, rule_id, category, value, line, col FROM findings
             WHERE (?1 IS NULL OR asset_url = ?1) AND (?2 IS NULL OR category LIKE ?2 || '%')
             ORDER BY asset_url, line, col",
        )?;
        let rows = stmt.query_map(params![asset_url, category_prefix], |r| {
            Ok(FindingRow {
                asset_url: r.get(0)?,
                rule_id: r.get(1)?,
                category: r.get(2)?,
                value: r.get(3)?,
                line: r.get(4)?,
                column: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn finding_count(&self, asset_url: &str) -> rusqlite::Result<usize> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE asset_url = ?1",
                [asset_url],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as usize)
    }

    pub fn sourcemap_of(&self, js_url: &str) -> rusqlite::Result<Option<(String, usize)>> {
        self.conn()
            .query_row(
                "SELECT map_url, sources FROM sourcemaps WHERE js_url = ?1",
                [js_url],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as usize)),
            )
            .optional()
    }

    /// Delete everything (`truncate` command).
    pub fn truncate(&self) -> rusqlite::Result<()> {
        self.conn().execute_batch(
            "DELETE FROM assets; DELETE FROM relations; DELETE FROM findings; DELETE FROM sourcemaps;",
        )
    }
}

fn row_to_asset(r: &rusqlite::Row<'_>) -> rusqlite::Result<AssetRow> {
    let kind: String = r.get(1)?;
    Ok(AssetRow {
        url: r.get(0)?,
        kind: AssetKind::parse(&kind).unwrap_or(AssetKind::Js),
        path: r.get(2)?,
        sha256: r.get(3)?,
        size: r.get::<_, i64>(4)? as u64,
        origin: r.get(5)?,
        parent_url: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(url: &str) -> AssetRow {
        AssetRow {
            url: url.into(),
            kind: AssetKind::Js,
            path: "x/y.js".into(),
            sha256: "abc".into(),
            size: 3,
            origin: "proxy".into(),
            parent_url: None,
        }
    }

    #[test]
    fn assets_relations_findings_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_asset(&row("https://a.test/1.js")).unwrap();
        db.upsert_asset(&row("https://a.test/1.js")).unwrap(); // upsert, not dup
        db.upsert_asset(&row("https://b.test/2.js")).unwrap();
        assert_eq!(db.assets(None, 10, 0).unwrap().len(), 2);
        assert_eq!(db.assets(Some("b.test"), 10, 0).unwrap().len(), 1);
        assert_eq!(
            db.asset_hash("https://a.test/1.js").unwrap().as_deref(),
            Some("abc")
        );

        db.add_relation("https://a.test/", "https://a.test/1.js")
            .unwrap();
        assert_eq!(
            db.scripts_of("https://a.test/").unwrap(),
            vec!["https://a.test/1.js"]
        );
        assert_eq!(
            db.pages_of("https://a.test/1.js").unwrap(),
            vec!["https://a.test/"]
        );

        let f = Finding {
            rule: "test",
            category: "Data/Paths/API".into(),
            value: "/api/v1".into(),
            line: 1,
            column: 2,
        };
        db.replace_findings("https://a.test/1.js", &[f.clone(), f])
            .unwrap();
        assert_eq!(db.finding_count("https://a.test/1.js").unwrap(), 1);
        assert_eq!(db.findings(None, Some("Data/")).unwrap().len(), 1);
        assert_eq!(db.findings(None, Some("Client")).unwrap().len(), 0);

        db.truncate().unwrap();
        assert!(db.assets(None, 10, 0).unwrap().is_empty());
    }
}
