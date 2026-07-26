use crate::config;
use crate::cve::filter::build_search_query;
use crate::cve::model::{CveFilter, CveRecord, CveReference, CveStatus, CveSummary};

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, params};
use std::collections::BTreeSet;
use std::path::Path;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY NOT NULL,
    published TEXT,
    modified TEXT,
    description TEXT NOT NULL DEFAULT '',
    cvss_v31 REAL,
    cvss_v40 REAL,
    severity TEXT,
    vector_v31 TEXT,
    in_kev INTEGER NOT NULL DEFAULT 0,
    kev_date_added TEXT,
    kev_due_date TEXT,
    epss_score REAL,
    epss_percentile REAL,
    sources TEXT NOT NULL DEFAULT '[]',
    fts_text TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    vendor TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    version_start TEXT,
    version_end TEXT
);
CREATE INDEX IF NOT EXISTS idx_cve_products_cve ON cve_products(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_products_vendor ON cve_products(vendor);
CREATE INDEX IF NOT EXISTS idx_cve_products_product ON cve_products(product);

CREATE TABLE IF NOT EXISTS cve_cwes (
    cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    cwe TEXT NOT NULL,
    PRIMARY KEY (cve_id, cwe)
);

CREATE TABLE IF NOT EXISTS cve_refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source TEXT,
    tags TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS cve_aliases (
    cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    alias_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, alias_id)
);

CREATE TABLE IF NOT EXISTS sync_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    records_added INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    error TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
    id UNINDEXED,
    description,
    products,
    cwes,
    refs_text
);
"#;

pub struct CveStore {
    conn: Connection,
}

impl CveStore {
    pub fn open() -> Result<Self> {
        let path = config::cve_db_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn =
            Connection::open(&path).with_context(|| format!("open cve db {}", path.display()))?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn open_at(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn upsert(&mut self, record: &CveRecord) -> Result<bool> {
        self.conn
            .execute_batch("SAVEPOINT chronosphere_cve_upsert")?;
        let result = (|| -> Result<bool> {
            let exists: bool = self
                .conn
                .query_row(
                    "SELECT 1 FROM cves WHERE id = ?1",
                    params![record.id],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            let mut merged = if exists {
                self.get(&record.id)?.unwrap_or_else(|| record.clone())
            } else {
                record.clone()
            };

            merge_record(&mut merged, record);

            let sources_json = serde_json::to_string(&merged.sources)?;
            let fts_text = build_fts_text(&merged);
            let now = Utc::now().to_rfc3339();

            self.conn.execute(
                r#"INSERT INTO cves (
                id, published, modified, description, cvss_v31, cvss_v40, severity,
                vector_v31, in_kev, kev_date_added, kev_due_date, epss_score,
                epss_percentile, sources, fts_text, updated_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)
            ON CONFLICT(id) DO UPDATE SET
                published=excluded.published, modified=excluded.modified,
                description=excluded.description, cvss_v31=excluded.cvss_v31,
                cvss_v40=excluded.cvss_v40, severity=excluded.severity,
                vector_v31=excluded.vector_v31, in_kev=excluded.in_kev,
                kev_date_added=excluded.kev_date_added, kev_due_date=excluded.kev_due_date,
                epss_score=excluded.epss_score, epss_percentile=excluded.epss_percentile,
                sources=excluded.sources, fts_text=excluded.fts_text, updated_at=excluded.updated_at
            "#,
                params![
                    merged.id,
                    merged.published,
                    merged.modified,
                    merged.description,
                    merged.cvss_v31,
                    merged.cvss_v40,
                    merged.severity,
                    merged.vector_v31,
                    merged.in_kev as i32,
                    merged.kev_date_added,
                    merged.kev_due_date,
                    merged.epss_score,
                    merged.epss_percentile,
                    sources_json,
                    fts_text,
                    now,
                ],
            )?;

            self.replace_children(&merged)?;
            self.rebuild_fts_row(&merged)?;

            Ok(!exists)
        })();
        match result {
            Ok(value) => {
                self.conn
                    .execute_batch("RELEASE SAVEPOINT chronosphere_cve_upsert")?;
                Ok(value)
            }
            Err(err) => {
                let _ = self.conn.execute_batch(
                "ROLLBACK TO SAVEPOINT chronosphere_cve_upsert;                              RELEASE SAVEPOINT chronosphere_cve_upsert",
            );
                Err(err)
            }
        }
    }

    fn replace_children(&mut self, record: &CveRecord) -> Result<()> {
        self.conn.execute(
            "DELETE FROM cve_products WHERE cve_id = ?1",
            params![record.id],
        )?;
        self.conn
            .execute("DELETE FROM cve_cwes WHERE cve_id = ?1", params![record.id])?;
        self.conn
            .execute("DELETE FROM cve_refs WHERE cve_id = ?1", params![record.id])?;
        self.conn.execute(
            "DELETE FROM cve_aliases WHERE cve_id = ?1",
            params![record.id],
        )?;

        for p in &record.products {
            self.conn.execute(
                "INSERT INTO cve_products (cve_id, vendor, product, version_start, version_end) VALUES (?1,?2,?3,?4,?5)",
                params![record.id, p.vendor, p.product, p.version_start, p.version_end],
            )?;
        }
        for cwe in &record.cwes {
            self.conn.execute(
                "INSERT OR IGNORE INTO cve_cwes (cve_id, cwe) VALUES (?1,?2)",
                params![record.id, cwe],
            )?;
        }
        for r in &record.references {
            let tags = serde_json::to_string(&r.tags)?;
            self.conn.execute(
                "INSERT INTO cve_refs (cve_id, url, source, tags) VALUES (?1,?2,?3,?4)",
                params![record.id, r.url, r.source, tags],
            )?;
        }
        for alias in &record.aliases {
            self.conn.execute(
                "INSERT OR IGNORE INTO cve_aliases (cve_id, alias_id) VALUES (?1,?2)",
                params![record.id, alias],
            )?;
        }
        Ok(())
    }

    fn rebuild_fts_row(&mut self, record: &CveRecord) -> Result<()> {
        let products: String = record
            .products
            .iter()
            .map(|p| format!("{} {}", p.vendor, p.product))
            .collect::<Vec<_>>()
            .join(" ");
        let cwes = record.cwes.join(" ");
        let refs_text: String = record
            .references
            .iter()
            .map(|r| r.url.as_str())
            .collect::<Vec<_>>()
            .join(" ");

        self.conn
            .execute("DELETE FROM cves_fts WHERE id = ?1", params![record.id])?;
        self.conn.execute(
            "INSERT INTO cves_fts (id, description, products, cwes, refs_text) VALUES (?1,?2,?3,?4,?5)",
            params![record.id, record.description, products, cwes, refs_text],
        )?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<CveRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, published, modified, description, cvss_v31, cvss_v40, severity,
                    vector_v31, in_kev, kev_date_added, kev_due_date, epss_score, epss_percentile, sources
             FROM cves WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let sources_str: String = row.get(13)?;
            let sources: BTreeSet<String> = serde_json::from_str(&sources_str).unwrap_or_default();
            let mut rec = CveRecord {
                id: row.get(0)?,
                published: row.get(1)?,
                modified: row.get(2)?,
                description: row.get(3)?,
                cvss_v31: row.get(4)?,
                cvss_v40: row.get(5)?,
                severity: row.get(6)?,
                vector_v31: row.get(7)?,
                in_kev: row.get::<_, i32>(8)? != 0,
                kev_date_added: row.get(9)?,
                kev_due_date: row.get(10)?,
                epss_score: row.get(11)?,
                epss_percentile: row.get(12)?,
                sources,
                ..Default::default()
            };
            rec.products = self.load_products(&rec.id)?;
            rec.cwes = self.load_cwes(&rec.id)?;
            rec.references = self.load_refs(&rec.id)?;
            rec.aliases = self.load_aliases(&rec.id)?;
            Ok(Some(rec))
        } else {
            Ok(None)
        }
    }

    fn load_products(&self, cve_id: &str) -> Result<Vec<crate::cve::model::CveProduct>> {
        let mut stmt = self.conn.prepare(
            "SELECT vendor, product, version_start, version_end FROM cve_products WHERE cve_id = ?1",
        )?;
        let rows = stmt.query_map(params![cve_id], |r| {
            Ok(crate::cve::model::CveProduct {
                vendor: r.get(0)?,
                product: r.get(1)?,
                version_start: r.get(2)?,
                version_end: r.get(3)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn load_cwes(&self, cve_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT cwe FROM cve_cwes WHERE cve_id = ?1")?;
        let rows = stmt.query_map(params![cve_id], |r| r.get(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn load_refs(&self, cve_id: &str) -> Result<Vec<CveReference>> {
        let mut stmt = self
            .conn
            .prepare("SELECT url, source, tags FROM cve_refs WHERE cve_id = ?1")?;
        let rows = stmt.query_map(params![cve_id], |r| {
            let tags_str: String = r.get(2)?;
            Ok(CveReference {
                url: r.get(0)?,
                source: r.get(1)?,
                tags: serde_json::from_str(&tags_str).unwrap_or_default(),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn load_aliases(&self, cve_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT alias_id FROM cve_aliases WHERE cve_id = ?1")?;
        let rows = stmt.query_map(params![cve_id], |r| r.get(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn search(&self, filter: &CveFilter) -> Result<Vec<CveRecord>> {
        let (sql, params_vec) = build_search_query(filter);
        let mut stmt = self.conn.prepare(&sql)?;
        let ids: Vec<String> = Self::query_ids(&mut stmt, &params_vec)?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(rec) = self.get(&id)? {
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// List/browse projection: one query, no child-table hydration. Use this
    /// for the paged browse view; hydrate a full [`CveRecord`] via [`Self::get`]
    /// only when a single record's detail is opened.
    pub fn search_summaries(&self, filter: &CveFilter) -> Result<Vec<CveSummary>> {
        let (sql, params_vec) = crate::cve::filter::build_summary_query(filter);
        let mut stmt = self.conn.prepare(&sql)?;
        let refs = Self::params_as_refs(&params_vec);
        let rows = stmt.query_map(refs.as_slice(), |r| {
            Ok(CveSummary {
                id: r.get(0)?,
                severity: r.get(1)?,
                cvss_v31: r.get(2)?,
                in_kev: r.get::<_, i32>(3)? != 0,
                description: r.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Total number of rows matching the filter, ignoring limit/offset.
    pub fn count(&self, filter: &CveFilter) -> Result<u64> {
        let (sql, params_vec) = crate::cve::filter::build_count_query(filter);
        let refs = Self::params_as_refs(&params_vec);
        let n: u64 = self.conn.query_row(&sql, refs.as_slice(), |r| r.get(0))?;
        Ok(n)
    }

    fn query_ids(
        stmt: &mut rusqlite::Statement,
        params_vec: &[rusqlite::types::Value],
    ) -> Result<Vec<String>> {
        let refs = Self::params_as_refs(params_vec);
        let rows = stmt.query_map(refs.as_slice(), |r| r.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn params_as_refs(params_vec: &[rusqlite::types::Value]) -> Vec<&dyn rusqlite::ToSql> {
        // Store bindings in a vec of enum wrappers so references live long enough.
        // We re-bind per query call on the stack via match.
        params_vec
            .iter()
            .map(|v| -> &dyn rusqlite::ToSql {
                match v {
                    rusqlite::types::Value::Text(s) => s,
                    rusqlite::types::Value::Real(r) => r,
                    rusqlite::types::Value::Integer(i) => i,
                    rusqlite::types::Value::Blob(b) => b,
                    rusqlite::types::Value::Null => &rusqlite::types::Null,
                }
            })
            .collect()
    }

    pub fn status(&self) -> Result<CveStatus> {
        let total: u64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM cves", [], |r| r.get(0))?;
        let kev_count: u64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM cves WHERE in_kev = 1", [], |r| {
                    r.get(0)
                })?;
        let last_sync: Option<String> = self
            .conn
            .query_row(
                "SELECT finished_at FROM sync_runs WHERE status = 'ok' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();
        let last_sync = last_sync.and_then(|s| s.parse().ok());
        Ok(CveStatus {
            total,
            kev_count,
            db_path: config::cve_db_path().display().to_string(),
            db_size_bytes: config::cve_storage_size_bytes(),
            last_sync,
            last_nvd_feed: crate::cve::config::SyncState::load()
                .feeds
                .get("nvdcve-2.0-modified")
                .and_then(|f| f.imported_at.clone()),
        })
    }

    pub fn mark_kev(&mut self, id: &str, date_added: &str, due_date: Option<&str>) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE cves SET in_kev = 1, kev_date_added = ?2, kev_due_date = ?3 WHERE id = ?1",
            params![id, date_added, due_date],
        )?;
        Ok(n > 0)
    }

    pub fn update_epss(&mut self, id: &str, score: f64, percentile: f64) -> Result<()> {
        self.conn.execute(
            "UPDATE cves SET epss_score = ?2, epss_percentile = ?3 WHERE id = ?1",
            params![id, score, percentile],
        )?;
        Ok(())
    }

    pub fn ids_for_osv_enrich(&self, since: Option<&str>, limit: u32) -> Result<Vec<String>> {
        if let Some(s) = since {
            let sql = format!(
                "SELECT id FROM cves WHERE modified > ?1 OR updated_at > ?1 ORDER BY modified DESC LIMIT {limit}"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(params![s], |r| r.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        } else {
            let sql = format!("SELECT id FROM cves ORDER BY modified DESC LIMIT {limit}");
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        }
    }

    pub fn log_sync_run(
        &mut self,
        provider: &str,
        started: &str,
        finished: &str,
        status: &str,
        added: u64,
        updated: u64,
        error: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sync_runs (provider, started_at, finished_at, status, records_added, records_updated, error)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![provider, started, finished, status, added, updated, error],
        )?;
        Ok(())
    }
}

fn merge_record(existing: &mut CveRecord, incoming: &CveRecord) {
    if incoming.published.is_some() {
        existing.published = incoming.published.clone();
    }
    if incoming.modified.is_some() {
        existing.modified = incoming.modified.clone();
    }
    if !incoming.description.is_empty() {
        existing.description = incoming.description.clone();
    }
    if incoming.cvss_v31.is_some() {
        existing.cvss_v31 = incoming.cvss_v31;
    }
    if incoming.cvss_v40.is_some() {
        existing.cvss_v40 = incoming.cvss_v40;
    }
    if incoming.severity.is_some() {
        existing.severity = incoming.severity.clone();
    }
    if incoming.vector_v31.is_some() {
        existing.vector_v31 = incoming.vector_v31.clone();
    }
    if incoming.in_kev {
        existing.in_kev = true;
    }
    if incoming.kev_date_added.is_some() {
        existing.kev_date_added = incoming.kev_date_added.clone();
    }
    if incoming.kev_due_date.is_some() {
        existing.kev_due_date = incoming.kev_due_date.clone();
    }
    if incoming.epss_score.is_some() {
        existing.epss_score = incoming.epss_score;
    }
    if incoming.epss_percentile.is_some() {
        existing.epss_percentile = incoming.epss_percentile;
    }
    existing.sources.extend(incoming.sources.iter().cloned());
    if !incoming.products.is_empty() {
        existing.products = incoming.products.clone();
    }
    if !incoming.cwes.is_empty() {
        existing.cwes = incoming.cwes.clone();
    }
    if !incoming.references.is_empty() {
        existing.references = incoming.references.clone();
    }
    for a in &incoming.aliases {
        if !existing.aliases.contains(a) {
            existing.aliases.push(a.clone());
        }
    }
}

fn build_fts_text(record: &CveRecord) -> String {
    let products: String = record
        .products
        .iter()
        .map(|p| format!("{} {}", p.vendor, p.product))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} {} {} {}",
        record.id,
        record.description,
        products,
        record.cwes.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve::model::{CveProduct, severity_from_score};

    #[test]
    fn upsert_and_search() {
        let dir = std::env::temp_dir().join(format!("chrono-cve-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("test.db");
        let mut store = CveStore::open_at(&db).unwrap();

        let mut rec = CveRecord {
            id: "CVE-2026-9256".into(),
            description: "NGINX heap overflow remote code execution".into(),
            cvss_v31: Some(8.1),
            severity: Some(severity_from_score(8.1).into()),
            products: vec![CveProduct {
                vendor: "f5".into(),
                product: "nginx".into(),
                ..Default::default()
            }],
            cwes: vec!["CWE-122".into()],
            ..Default::default()
        };
        rec.sources.insert("nvd".into());
        assert!(store.upsert(&rec).unwrap());

        let filter = CveFilter {
            query: Some("nginx".into()),
            limit: 10,
            ..Default::default()
        };
        let hits = store.search(&filter).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "CVE-2026-9256");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn summaries_paginate_and_count() {
        let dir = std::env::temp_dir().join(format!("chrono-cve-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("test.db");
        let mut store = CveStore::open_at(&db).unwrap();

        for i in 0..25 {
            let mut rec = CveRecord {
                id: format!("CVE-2026-{:04}", 1000 + i),
                modified: Some(format!("2026-01-{:02}T00:00:00Z", (i % 28) + 1)),
                description: "sample vulnerability".into(),
                cvss_v31: Some(7.5),
                severity: Some(severity_from_score(7.5).into()),
                ..Default::default()
            };
            rec.sources.insert("nvd".into());
            store.upsert(&rec).unwrap();
        }

        let all = CveFilter {
            limit: 10,
            ..Default::default()
        };
        assert_eq!(store.count(&all).unwrap(), 25);

        let page0 = store.search_summaries(&all).unwrap();
        assert_eq!(page0.len(), 10);

        let page2 = store
            .search_summaries(&CveFilter {
                limit: 10,
                offset: 20,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page2.len(), 5);

        // Pages must not overlap.
        let first_ids: std::collections::HashSet<_> = page0.iter().map(|s| s.id.clone()).collect();
        assert!(page2.iter().all(|s| !first_ids.contains(&s.id)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
