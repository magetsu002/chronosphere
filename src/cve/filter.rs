use crate::cve::model::CveFilter;
use crate::cve::poc_index::PocIndex;
use rusqlite::types::Value;

const ORDER_BY: &str = "ORDER BY c.modified DESC NULLS LAST, c.id DESC";

/// Build the shared `WHERE` clause (with `c.` column prefixes) and its bound
/// parameters. Reused by the id, summary and count query builders so every
/// path filters identically.
fn build_where(filter: &CveFilter) -> (String, Vec<Value>) {
    let mut params: Vec<Value> = Vec::new();
    let mut where_clauses: Vec<String> = Vec::new();

    if let Some(ref q) = filter.query {
        let fts_q = q
            .split_whitespace()
            .map(|w| format!("\"{w}\""))
            .collect::<Vec<_>>()
            .join(" ");
        where_clauses.push(format!(
            "c.id IN (SELECT id FROM cves_fts WHERE cves_fts MATCH ?{})",
            params.len() + 1
        ));
        params.push(Value::Text(fts_q));
    }

    if let Some(ref product) = filter.product {
        where_clauses.push(format!(
            "c.id IN (SELECT cve_id FROM cve_products WHERE product LIKE ?{} OR vendor LIKE ?{})",
            params.len() + 1,
            params.len() + 2
        ));
        let pat = format!("%{product}%");
        params.push(Value::Text(pat.clone()));
        params.push(Value::Text(pat));
    }

    if let Some(ref vendor) = filter.vendor {
        where_clauses.push(format!(
            "c.id IN (SELECT cve_id FROM cve_products WHERE vendor LIKE ?{})",
            params.len() + 1
        ));
        params.push(Value::Text(format!("%{vendor}%")));
    }

    if let Some(ref cwe) = filter.cwe {
        let cwe_norm = if cwe.starts_with("CWE-") {
            cwe.clone()
        } else {
            format!("CWE-{cwe}")
        };
        where_clauses.push(format!(
            "c.id IN (SELECT cve_id FROM cve_cwes WHERE cwe = ?{})",
            params.len() + 1
        ));
        params.push(Value::Text(cwe_norm));
    }

    if let Some(ref sev) = filter.severity {
        where_clauses.push(format!("UPPER(c.severity) = ?{}", params.len() + 1));
        params.push(Value::Text(sev.to_uppercase()));
    }

    if filter.kev_only {
        where_clauses.push("c.in_kev = 1".into());
    }

    if filter.poc_only {
        let ids = PocIndex::global().cve_ids();
        if ids.is_empty() {
            // No ready PoCs indexed — match nothing.
            where_clauses.push("0".into());
        } else {
            let start = params.len() + 1;
            let placeholders: Vec<String> =
                (0..ids.len()).map(|i| format!("?{}", start + i)).collect();
            where_clauses.push(format!("c.id IN ({})", placeholders.join(", ")));
            for id in ids {
                params.push(Value::Text(id));
            }
        }
    }

    if let Some(min) = filter.min_epss {
        where_clauses.push(format!("c.epss_score >= ?{}", params.len() + 1));
        params.push(Value::Real(min));
    }

    if let Some(days) = filter.since_days {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
        where_clauses.push(format!("c.published >= ?{}", params.len() + 1));
        params.push(Value::Text(cutoff.format("%Y-%m-%d").to_string()));
    }

    if let Some(ref tag) = filter.tag {
        where_clauses.push(format!(
            "(c.description LIKE ?{} OR c.fts_text LIKE ?{})",
            params.len() + 1,
            params.len() + 2
        ));
        let pat = format!("%{tag}%");
        params.push(Value::Text(pat.clone()));
        params.push(Value::Text(pat));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    (where_sql, params)
}

fn page_bounds(filter: &CveFilter) -> (usize, usize) {
    (filter.limit.max(1).min(500), filter.offset)
}

/// Build SQL that returns only matching CVE ids for a page.
pub fn build_search_query(filter: &CveFilter) -> (String, Vec<Value>) {
    let (where_sql, params) = build_where(filter);
    let (limit, offset) = page_bounds(filter);
    let sql =
        format!("SELECT c.id FROM cves c {where_sql} {ORDER_BY} LIMIT {limit} OFFSET {offset}");
    (sql, params)
}

/// Build SQL that returns the columns needed for the list/browse view in a
/// single query, skipping the child-table joins used by the detail view.
pub fn build_summary_query(filter: &CveFilter) -> (String, Vec<Value>) {
    let (where_sql, params) = build_where(filter);
    let (limit, offset) = page_bounds(filter);
    let sql = format!(
        "SELECT c.id, c.severity, c.cvss_v31, c.in_kev, c.description \
         FROM cves c {where_sql} {ORDER_BY} LIMIT {limit} OFFSET {offset}"
    );
    (sql, params)
}

/// Build SQL that counts all rows matching the filter (ignores limit/offset),
/// used to drive pagination totals.
pub fn build_count_query(filter: &CveFilter) -> (String, Vec<Value>) {
    let (where_sql, params) = build_where(filter);
    let sql = format!("SELECT COUNT(*) FROM cves c {where_sql}");
    (sql, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_kev_filter() {
        let f = CveFilter {
            kev_only: true,
            limit: 20,
            ..Default::default()
        };
        let (sql, _) = build_search_query(&f);
        assert!(sql.contains("in_kev = 1"));
    }

    #[test]
    fn builds_poc_filter_empty_index() {
        // Without CHRONO_POC_ROOT / ~/pocs, the global index is typically empty
        // and poc_only must still produce valid SQL that matches nothing.
        let f = CveFilter {
            poc_only: true,
            limit: 20,
            ..Default::default()
        };
        let (sql, params) = build_search_query(&f);
        if PocIndex::global().is_empty() {
            assert!(sql.contains("WHERE 0"));
            assert!(params.is_empty());
        } else {
            assert!(sql.contains("c.id IN ("));
            assert_eq!(params.len(), PocIndex::global().len());
        }
    }

    #[test]
    fn summary_query_includes_offset() {
        let f = CveFilter {
            limit: 50,
            offset: 150,
            ..Default::default()
        };
        let (sql, _) = build_summary_query(&f);
        assert!(sql.contains("LIMIT 50 OFFSET 150"));
        assert!(sql.contains("c.description"));
    }

    #[test]
    fn count_query_ignores_limit() {
        let f = CveFilter {
            kev_only: true,
            limit: 10,
            offset: 20,
            ..Default::default()
        };
        let (sql, _) = build_count_query(&f);
        assert!(sql.contains("COUNT(*)"));
        assert!(sql.contains("in_kev = 1"));
        assert!(!sql.contains("LIMIT"));
        assert!(!sql.contains("OFFSET"));
    }
}
