use crate::cve::model::{CveProduct, CveRecord, CveReference};
use crate::cve::rate_limit::HttpClient;
use crate::cve::store::CveStore;

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;

const OSV_BASE: &str = "https://api.osv.dev/v1/vulns";

pub async fn enrich_cve(client: &HttpClient, store: &mut CveStore, cve_id: &str) -> Result<bool> {
    let url = format!("{OSV_BASE}/{cve_id}");
    let resp = client.get("osv", &url).await?;
    if resp.status().as_u16() == 404 {
        return Ok(false);
    }
    let text = resp.text().await?;
    let root: Value = serde_json::from_str(&text).context("parse osv json")?;
    let Some(rec) = parse_osv(&root, cve_id) else {
        return Ok(false);
    };
    store.upsert(&rec)?;
    Ok(true)
}

pub async fn enrich_batch(
    client: &HttpClient,
    store: &mut CveStore,
    ids: &[String],
    progress: bool,
) -> Result<u64> {
    let mut ok = 0u64;
    let total = ids.len();
    for (i, id) in ids.iter().enumerate() {
        if progress && (i == 0 || (i + 1) % 25 == 0 || i + 1 == total) {
            eprintln!("cve sync: OSV {}/{}…", i + 1, total);
        }
        match enrich_cve(client, store, id).await {
            Ok(true) => ok += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!(cve = %id, ?e, "osv enrich failed"),
        }
    }
    Ok(ok)
}

fn parse_osv(root: &Value, expected_cve: &str) -> Option<CveRecord> {
    let id = root.get("id")?.as_str()?.to_string();
    // OSV may use CVE as id directly, or GHSA with CVE in aliases
    let mut aliases: Vec<String> = root
        .get("aliases")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let cve_id = if id.starts_with("CVE-") {
        id.clone()
    } else if aliases.iter().any(|a| a == expected_cve) {
        expected_cve.to_string()
    } else if let Some(cve) = aliases.iter().find(|a| a.starts_with("CVE-")) {
        cve.clone()
    } else {
        return None;
    };

    if !aliases.contains(&cve_id) && id != cve_id {
        aliases.push(id.clone());
    }

    let description = root
        .get("summary")
        .or_else(|| root.get("details"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let published = root
        .get("published")
        .and_then(|v| v.as_str())
        .map(String::from);
    let modified = root
        .get("modified")
        .and_then(|v| v.as_str())
        .map(String::from);

    let mut products = Vec::new();
    if let Some(arr) = root.get("affected").and_then(|v| v.as_array()) {
        for aff in arr {
            let pkg = aff.get("package").unwrap_or(aff);
            let ecosystem = pkg.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("");
            let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
            products.push(CveProduct {
                vendor: ecosystem.to_lowercase(),
                product: name.to_string(),
                ..Default::default()
            });
        }
    }

    let mut references = Vec::new();
    if let Some(arr) = root.get("references").and_then(|v| v.as_array()) {
        for r in arr {
            if let Some(url) = r.get("url").and_then(|v| v.as_str()) {
                references.push(CveReference {
                    url: url.to_string(),
                    source: Some("osv".into()),
                    tags: vec![],
                });
            }
        }
    }

    let mut sources = BTreeSet::new();
    sources.insert("osv".into());

    Some(CveRecord {
        id: cve_id,
        published,
        modified,
        description,
        products,
        references,
        aliases,
        sources,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_as_osv_id() {
        let json =
            r#"{"id":"CVE-2021-44228","summary":"Log4Shell","aliases":["GHSA-jfh8-c2jp-5v3q"]}"#;
        let root: Value = serde_json::from_str(json).unwrap();
        let rec = parse_osv(&root, "CVE-2021-44228").unwrap();
        assert_eq!(rec.id, "CVE-2021-44228");
    }

    #[test]
    fn ghsa_with_cve_alias() {
        let json =
            r#"{"id":"GHSA-jfh8-c2jp-5v3q","summary":"Log4Shell","aliases":["CVE-2021-44228"]}"#;
        let root: Value = serde_json::from_str(json).unwrap();
        let rec = parse_osv(&root, "CVE-2021-44228").unwrap();
        assert_eq!(rec.id, "CVE-2021-44228");
    }
}
