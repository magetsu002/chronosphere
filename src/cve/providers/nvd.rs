use crate::cve::config::SyncState;
use crate::cve::model::{
    CveProduct, CveRecord, CveReference, MonthSync, NvdMonthField, severity_from_score,
};
use crate::cve::rate_limit::HttpClient;
use crate::cve::store::CveStore;

use anyhow::{Context, Result, bail};
use chrono::NaiveDate;
use flate2::read::GzDecoder;
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Read;

const NVD_FEED_BASE: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";
const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

pub struct NvdFeedMeta {
    pub sha256: String,
    pub last_modified: Option<String>,
}

pub async fn fetch_feed_meta(client: &HttpClient, feed_name: &str) -> Result<NvdFeedMeta> {
    let url = format!("{NVD_FEED_BASE}/{feed_name}.meta");
    let resp = client.get("nvd", &url).await?;
    let text = resp.text().await?;
    let mut sha256 = String::new();
    let mut last_modified = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("sha256:") {
            sha256 = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("lastModifiedDate:") {
            last_modified = Some(v.trim().to_string());
        }
    }
    if sha256.is_empty() {
        bail!("no sha256 in meta for {feed_name}");
    }
    Ok(NvdFeedMeta {
        sha256,
        last_modified,
    })
}

pub async fn download_and_import_feed(
    client: &HttpClient,
    store: &mut CveStore,
    feed_name: &str,
    state: &mut SyncState,
) -> Result<(u64, u64)> {
    let meta = fetch_feed_meta(client, feed_name).await?;
    if !state.feed_changed(feed_name, &meta.sha256) {
        tracing::info!(feed = feed_name, "unchanged, skipping");
        return Ok((0, 0));
    }

    let url = format!("{NVD_FEED_BASE}/{feed_name}.json.gz");
    tracing::info!(feed = feed_name, "downloading");
    let resp = client.get("nvd", &url).await?;
    let bytes = resp.bytes().await?;
    let mut decoder = GzDecoder::new(&bytes[..]);
    let mut json = String::new();
    decoder.read_to_string(&mut json)?;

    let added = import_nvd_json(store, &json)?;
    let updated = 0u64; // upsert returns added vs updated per-record internally
    state.mark_feed(feed_name, &meta.sha256, meta.last_modified.as_deref());
    Ok((added, updated))
}

pub fn import_nvd_json(store: &mut CveStore, json: &str) -> Result<u64> {
    let (added, updated) = import_nvd_json_stats(store, json)?;
    Ok(added + updated)
}

pub fn import_nvd_json_stats(store: &mut CveStore, json: &str) -> Result<(u64, u64)> {
    let root: Value = serde_json::from_str(json).context("parse nvd json")?;
    let vulns = root
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .context("missing vulnerabilities array")?;
    let mut added = 0u64;
    let mut updated = 0u64;
    for item in vulns {
        if let Some(rec) = parse_nvd_item(item) {
            if store.upsert(&rec)? {
                added += 1;
            } else {
                updated += 1;
            }
        }
    }
    Ok((added, updated))
}

pub fn parse_nvd_item(item: &Value) -> Option<CveRecord> {
    let cve = item.get("cve")?;
    let id = cve.get("id")?.as_str()?.to_string();
    let published = cve
        .get("published")
        .and_then(|v| v.as_str())
        .map(String::from);
    let modified = cve
        .get("lastModified")
        .and_then(|v| v.as_str())
        .map(String::from);
    let description = cve
        .get("descriptions")
        .and_then(|d| d.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|x| x.get("lang").and_then(|l| l.as_str()) == Some("en"))
                .and_then(|x| x.get("value").and_then(|v| v.as_str()))
        })
        .unwrap_or("")
        .to_string();

    let mut cvss_v31 = None;
    let mut cvss_v40 = None;
    let mut vector_v31 = None;
    let mut severity = None;

    if let Some(metrics) = cve.get("metrics") {
        if let Some(arr) = metrics.get("cvssMetricV31").and_then(|v| v.as_array()) {
            if let Some(m) = arr.first() {
                if let Some(data) = m.get("cvssData") {
                    cvss_v31 = data.get("baseScore").and_then(|v| v.as_f64());
                    vector_v31 = data
                        .get("vectorString")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    if let Some(s) = cvss_v31 {
                        severity = Some(severity_from_score(s).to_string());
                    }
                }
            }
        }
        if let Some(arr) = metrics.get("cvssMetricV40").and_then(|v| v.as_array()) {
            if let Some(m) = arr.first() {
                if let Some(data) = m.get("cvssData") {
                    cvss_v40 = data.get("baseScore").and_then(|v| v.as_f64());
                    if severity.is_none() {
                        if let Some(s) = cvss_v40 {
                            severity = Some(severity_from_score(s).to_string());
                        }
                    }
                }
            }
        }
    }

    let mut cwes = Vec::new();
    if let Some(arr) = cve.get("weaknesses").and_then(|v| v.as_array()) {
        for w in arr {
            if let Some(descs) = w.get("description").and_then(|d| d.as_array()) {
                for d in descs {
                    if let Some(val) = d.get("value").and_then(|v| v.as_str()) {
                        if val.starts_with("CWE-") {
                            cwes.push(val.to_string());
                        }
                    }
                }
            }
        }
    }

    let mut products = Vec::new();
    if let Some(configs) = cve.get("configurations").and_then(|v| v.as_array()) {
        for cfg in configs {
            if let Some(nodes) = cfg.get("nodes").and_then(|v| v.as_array()) {
                for node in nodes {
                    if let Some(matches) = node.get("cpeMatch").and_then(|v| v.as_array()) {
                        for m in matches {
                            if m.get("vulnerable").and_then(|v| v.as_bool()) != Some(true) {
                                continue;
                            }
                            if let Some(cpe) = m.get("criteria").and_then(|v| v.as_str()) {
                                let parts: Vec<&str> = cpe.split(':').collect();
                                if parts.len() >= 5 {
                                    products.push(CveProduct {
                                        vendor: parts[3].to_string(),
                                        product: parts[4].to_string(),
                                        version_start: m
                                            .get("versionStartIncluding")
                                            .or_else(|| m.get("versionStartExcluding"))
                                            .and_then(|v| v.as_str())
                                            .map(String::from),
                                        version_end: m
                                            .get("versionEndIncluding")
                                            .or_else(|| m.get("versionEndExcluding"))
                                            .and_then(|v| v.as_str())
                                            .map(String::from),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut references = Vec::new();
    if let Some(arr) = cve.get("references").and_then(|v| v.as_array()) {
        for r in arr {
            if let Some(url) = r.get("url").and_then(|v| v.as_str()) {
                let tags: Vec<String> = r
                    .get("tags")
                    .and_then(|t| t.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                references.push(CveReference {
                    url: url.to_string(),
                    source: r.get("source").and_then(|v| v.as_str()).map(String::from),
                    tags,
                });
            }
        }
    }

    let mut sources = BTreeSet::new();
    sources.insert("nvd".into());

    Some(CveRecord {
        id,
        published,
        modified,
        description,
        cvss_v31,
        cvss_v40,
        severity,
        vector_v31,
        products,
        cwes,
        references,
        sources,
        ..Default::default()
    })
}

pub async fn fetch_single_cve(
    client: &HttpClient,
    store: &mut CveStore,
    cve_id: &str,
    api_key: Option<&str>,
) -> Result<bool> {
    let url = format!("{NVD_API_BASE}?cveId={cve_id}");
    let resp = if let Some(key) = api_key {
        client.get_with_api_key("nvd", &url, key).await?
    } else {
        client.get("nvd", &url).await?
    };
    let text = resp.text().await?;
    let (added, updated) = import_nvd_json_stats(store, &text)?;
    Ok(added + updated > 0)
}

pub fn month_date_bounds(year: u16, month: u8) -> Result<(String, String)> {
    let y = i32::from(year);
    let m = u32::from(month);
    let first = NaiveDate::from_ymd_opt(y, m, 1).context("invalid month")?;
    let next_month = if m == 12 {
        NaiveDate::from_ymd_opt(y + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(y, m + 1, 1)
    }
    .context("invalid month boundary")?;
    let last = next_month.pred_opt().context("last day of month")?;
    let start = format!("{}T00:00:00.000", first.format("%Y-%m-%d"));
    let end = format!("{}T23:59:59.999", last.format("%Y-%m-%d"));
    Ok((start, end))
}

fn build_month_api_url(
    start: &str,
    end: &str,
    by_modified: bool,
    start_index: u32,
    results_per_page: u32,
) -> String {
    let (start_param, end_param) = if by_modified {
        ("lastModStartDate", "lastModEndDate")
    } else {
        ("pubStartDate", "pubEndDate")
    };
    format!(
        "{NVD_API_BASE}?{start_param}={start}&{end_param}={end}&startIndex={start_index}&resultsPerPage={results_per_page}"
    )
}

/// Fetch CVEs for one calendar month via the NVD 2.0 API (paginated date-range query).
pub async fn sync_by_month(
    client: &HttpClient,
    store: &mut CveStore,
    month: &MonthSync,
    api_key: Option<&str>,
    progress: bool,
) -> Result<(u64, u64)> {
    let (start, end) = month_date_bounds(month.year, month.month)?;
    let label = format!("{:04}-{:02}", month.year, month.month);
    let by_modified = month.field == NvdMonthField::Modified;
    let field = if by_modified { "modified" } else { "published" };
    tracing::info!(month = %label, field, "syncing NVD API date range");

    const RESULTS_PER_PAGE: u32 = 2000;
    let mut start_index = 0u32;
    let mut added = 0u64;
    let mut updated = 0u64;
    let mut total_results = 0u64;

    loop {
        let page = start_index / RESULTS_PER_PAGE + 1;
        let pages = total_results.div_ceil(u64::from(RESULTS_PER_PAGE)).max(1);
        if progress {
            if start_index == 0 {
                eprintln!("cve sync: NVD {label} ({field}): waiting for first page…");
            } else {
                eprintln!(
                    "cve sync: NVD {label} ({field}): page {page}/{pages} — {} CVEs imported so far",
                    added + updated
                );
            }
        }
        let url = build_month_api_url(&start, &end, by_modified, start_index, RESULTS_PER_PAGE);
        let resp = if let Some(key) = api_key {
            client.get_with_api_key("nvd", &url, key).await?
        } else {
            client.get("nvd", &url).await?
        };
        let text = resp.text().await?;
        let root: Value = serde_json::from_str(&text).context("parse nvd api response")?;
        if start_index == 0 {
            total_results = root
                .get("totalResults")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            tracing::info!(total = total_results, "NVD CVE count for month range");
            if progress {
                eprintln!("cve sync: NVD {label} ({field}): {total_results} CVEs reported by NVD");
            }
        }
        let (a, u) = import_nvd_json_stats(store, &text)?;
        added += a;
        updated += u;
        start_index += RESULTS_PER_PAGE;
        if start_index >= total_results as u32 || a + u == 0 {
            break;
        }
    }
    Ok((added, updated))
}

pub fn feed_name_for_year(year: u16) -> String {
    format!("nvdcve-2.0-{year}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_date_bounds_covers_full_month() {
        let (start, end) = month_date_bounds(2026, 5).unwrap();
        assert_eq!(start, "2026-05-01T00:00:00.000");
        assert_eq!(end, "2026-05-31T23:59:59.999");
    }

    #[test]
    fn build_month_url_uses_publish_dates() {
        let url = build_month_api_url(
            "2026-05-01T00:00:00.000",
            "2026-05-31T23:59:59.999",
            false,
            0,
            2000,
        );
        assert!(url.contains("pubStartDate=2026-05-01T00:00:00.000"));
        assert!(url.contains("pubEndDate=2026-05-31T23:59:59.999"));
        assert!(url.contains("startIndex=0"));
    }

    #[test]
    fn parses_nvd_snippet() {
        let json = r#"{"vulnerabilities":[{"cve":{"id":"CVE-2026-9256","published":"2026-05-22T00:00:00.000","lastModified":"2026-05-22T00:00:00.000","descriptions":[{"lang":"en","value":"NGINX heap overflow"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.1,"vectorString":"AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},"weaknesses":[{"description":[{"lang":"en","value":"CWE-122"}]}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}]}]}]}}]}"#;
        let root: Value = serde_json::from_str(json).unwrap();
        let rec = parse_nvd_item(&root["vulnerabilities"][0]).unwrap();
        assert_eq!(rec.id, "CVE-2026-9256");
        assert_eq!(rec.cvss_v31, Some(8.1));
        assert!(!rec.products.is_empty());
    }
}
