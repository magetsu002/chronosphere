use crate::cve::rate_limit::HttpClient;
use crate::cve::store::CveStore;

use anyhow::{Context, Result};
use serde::Deserialize;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Deserialize)]
struct KevFeed {
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
    #[serde(rename = "dueDate")]
    due_date: Option<String>,
}

pub async fn sync_kev(client: &HttpClient, store: &mut CveStore) -> Result<u64> {
    let resp = client.get("kev", KEV_URL).await?;
    let feed: KevFeed = resp.json().await.context("parse kev json")?;
    let mut count = 0u64;
    for entry in feed.vulnerabilities {
        if store.mark_kev(&entry.cve_id, &entry.date_added, entry.due_date.as_deref())? {
            count += 1;
        } else {
            // CVE not in DB yet — insert stub so KEV flag is preserved on next NVD sync
            let mut rec = crate::cve::model::CveRecord {
                id: entry.cve_id.clone(),
                in_kev: true,
                kev_date_added: Some(entry.date_added),
                kev_due_date: entry.due_date,
                ..Default::default()
            };
            rec.sources.insert("kev".into());
            store.upsert(&rec)?;
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kev_entry_camel_case() {
        let json = r#"{"title":"KEV","vulnerabilities":[{"cveID":"CVE-2024-21182","dateAdded":"2026-06-01","dueDate":"2026-06-04"}]}"#;
        let feed: KevFeed = serde_json::from_str(json).unwrap();
        assert_eq!(feed.vulnerabilities.len(), 1);
        assert_eq!(feed.vulnerabilities[0].cve_id, "CVE-2024-21182");
        assert_eq!(feed.vulnerabilities[0].date_added, "2026-06-01");
        assert_eq!(
            feed.vulnerabilities[0].due_date.as_deref(),
            Some("2026-06-04")
        );
    }
}
