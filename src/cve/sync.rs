use crate::cve::config::{CveConfig, SyncState, ensure_cve_dirs};
use crate::cve::model::{CveFilter, CveRecord, MonthSync, NvdMonthField, SyncOptions, SyncResult};
use crate::cve::providers::{circl, epss, kev, nvd, osv};
use crate::cve::rate_limit::{HttpClient, acquire_sync_lock};
use crate::cve::store::CveStore;

use anyhow::{Context, Result, bail};
use chrono::{NaiveDate, Utc};

fn sync_progress(options: &SyncOptions, msg: impl AsRef<str>) {
    if options.progress {
        eprintln!("{}", msg.as_ref());
    }
}

pub async fn sync(options: SyncOptions) -> Result<SyncResult> {
    let _guard = acquire_sync_lock().await?;
    ensure_cve_dirs()?;
    sync_progress(&options, "cve sync: starting…");
    let cfg = CveConfig::load();
    let client = HttpClient::new(&CveConfig::user_agent())?;
    client.register_provider("nvd", cfg.nvd_interval_ms()).await;
    client.register_provider("kev", 0).await;
    client
        .register_provider("osv", cfg.osv.min_interval_ms)
        .await;
    client.register_provider("epss", 0).await;
    if cfg.circl.enabled {
        client
            .register_provider("circl", cfg.circl.min_interval_ms)
            .await;
    }

    let mut store = CveStore::open()?;
    let mut state = SyncState::load();
    let started = Utc::now().to_rfc3339();
    let mut result = SyncResult::default();
    let providers = if options.providers.is_empty() {
        vec!["nvd".into(), "kev".into()]
    } else {
        options.providers.clone()
    };

    if providers.iter().any(|p| p == "nvd") {
        sync_progress(&options, "cve sync: fetching from NVD…");
        match sync_nvd(&client, &mut store, &mut state, &options, &cfg).await {
            Ok((a, u)) => {
                sync_progress(
                    &options,
                    &format!("cve sync: NVD done ({a} added, {u} updated)"),
                );
                result.added += a;
                result.updated += u;
            }
            Err(e) => result.errors.push(format!("nvd: {e}")),
        }
    }

    if providers.iter().any(|p| p == "kev") {
        sync_progress(&options, "cve sync: merging CISA KEV catalog…");
        match kev::sync_kev(&client, &mut store).await {
            Ok(n) => {
                sync_progress(&options, &format!("cve sync: KEV done ({n} entries)"));
                tracing::info!(kev = n, "merged KEV entries");
                result.updated += n;
            }
            Err(e) => result.errors.push(format!("kev: {e}")),
        }
    }

    if options.enrich_epss && cfg.epss.enabled {
        sync_progress(&options, "cve sync: downloading EPSS scores…");
        match epss::sync_epss(&client, &mut store, options.progress).await {
            Ok(n) => {
                sync_progress(
                    &options,
                    &format!("cve sync: EPSS done ({n} scores merged)"),
                );
                tracing::info!(epss = n, "updated EPSS scores");
                result.updated += n;
            }
            Err(e) => result.errors.push(format!("epss: {e}")),
        }
    }

    if options.enrich_osv {
        let since = state.last_osv_enrich.clone();
        let ids = store.ids_for_osv_enrich(since.as_deref(), cfg.osv.max_enrich_per_sync)?;
        if !ids.is_empty() {
            sync_progress(
                &options,
                &format!("cve sync: enriching {} CVEs via OSV…", ids.len()),
            );
            match osv::enrich_batch(&client, &mut store, &ids, options.progress).await {
                Ok(n) => {
                    sync_progress(&options, &format!("cve sync: OSV done ({n} enriched)"));
                    tracing::info!(osv = n, "OSV enriched");
                    result.updated += n;
                }
                Err(e) => result.errors.push(format!("osv: {e}")),
            }
        } else {
            sync_progress(&options, "cve sync: OSV skipped (no new CVEs to enrich)");
        }
        state.last_osv_enrich = Some(Utc::now().to_rfc3339());
    }

    state.last_sync = Some(Utc::now().to_rfc3339());
    state.save()?;

    let finished = Utc::now().to_rfc3339();
    let status = if result.errors.is_empty() {
        "ok"
    } else {
        "partial"
    };
    let err_msg = result.errors.join("; ");
    store.log_sync_run(
        "sync",
        &started,
        &finished,
        status,
        result.added,
        result.updated,
        if result.errors.is_empty() {
            None
        } else {
            Some(err_msg.as_str())
        },
    )?;

    Ok(result)
}

async fn sync_nvd(
    client: &HttpClient,
    store: &mut CveStore,
    state: &mut SyncState,
    options: &SyncOptions,
    cfg: &CveConfig,
) -> Result<(u64, u64)> {
    if let Some(ref month) = options.month {
        let api_key = CveConfig::nvd_api_key();
        return nvd::sync_by_month(client, store, month, api_key.as_deref(), options.progress)
            .await;
    }

    let mut added = 0u64;
    let mut updated = 0u64;

    if options.full {
        let years = if options.years.is_empty() {
            cfg.sync.default_years.clone()
        } else {
            options.years.clone()
        };
        for year in years {
            let feed = nvd::feed_name_for_year(year);
            sync_progress(options, &format!("cve sync: downloading feed {feed}…"));
            let (a, u) = nvd::download_and_import_feed(client, store, &feed, state).await?;
            added += a;
            updated += u;
        }
    } else {
        for feed in ["nvdcve-2.0-modified", "nvdcve-2.0-recent"] {
            sync_progress(options, &format!("cve sync: downloading feed {feed}…"));
            let (a, u) = nvd::download_and_import_feed(client, store, feed, state).await?;
            added += a;
            updated += u;
        }
    }
    Ok((added, updated))
}

pub async fn fetch_one(cve_id: &str, enrich: bool) -> Result<Option<CveRecord>> {
    let id = crate::cve::model::normalize_cve_id(cve_id)
        .ok_or_else(|| anyhow::anyhow!("invalid CVE id: {cve_id}"))?;
    ensure_cve_dirs()?;
    let cfg = CveConfig::load();
    let client = HttpClient::new(&CveConfig::user_agent())?;
    client.register_provider("nvd", cfg.nvd_interval_ms()).await;
    client
        .register_provider("osv", cfg.osv.min_interval_ms)
        .await;
    if cfg.circl.enabled {
        client
            .register_provider("circl", cfg.circl.min_interval_ms)
            .await;
    }

    let mut store = CveStore::open()?;
    let api_key = CveConfig::nvd_api_key();
    nvd::fetch_single_cve(&client, &mut store, &id, api_key.as_deref()).await?;

    if enrich {
        let _ = osv::enrich_cve(&client, &mut store, &id).await;
        if cfg.circl.enabled {
            let _ = circl::enrich_cve(&client, &mut store, &id).await;
        }
    }

    store.get(&id)
}

pub fn search(filter: CveFilter) -> Result<Vec<CveRecord>> {
    ensure_cve_dirs()?;
    let store = CveStore::open()?;
    store.search(&filter)
}

pub fn show(cve_id: &str) -> Result<Option<CveRecord>> {
    let id = crate::cve::model::normalize_cve_id(cve_id)
        .ok_or_else(|| anyhow::anyhow!("invalid CVE id: {cve_id}"))?;
    ensure_cve_dirs()?;
    let store = CveStore::open()?;
    store.get(&id)
}

pub fn status() -> Result<crate::cve::model::CveStatus> {
    ensure_cve_dirs()?;
    let store = CveStore::open()?;
    store.status()
}

pub fn parse_month(s: &str, by_modified: bool) -> Result<MonthSync> {
    let s = s.trim();
    let (year_str, month_str) = if let Some((y, m)) = s.split_once('-') {
        (y, m)
    } else if s.len() == 6 && s.chars().all(|c| c.is_ascii_digit()) {
        (&s[..4], &s[4..])
    } else {
        bail!("invalid month: {s} (expected YYYY-MM)");
    };
    let year: u16 = year_str.parse().context("year")?;
    let month: u8 = month_str.parse().context("month")?;
    if !(1..=12).contains(&month) {
        bail!("month must be 1-12, got {month}");
    }
    NaiveDate::from_ymd_opt(i32::from(year), u32::from(month), 1)
        .ok_or_else(|| anyhow::anyhow!("invalid month: {s}"))?;
    Ok(MonthSync {
        year,
        month,
        field: if by_modified {
            NvdMonthField::Modified
        } else {
            NvdMonthField::Published
        },
    })
}

pub fn parse_years(s: &str) -> Result<Vec<u16>> {
    if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            bail!("invalid year range: {s}");
        }
        let start: u16 = parts[0].parse().context("year start")?;
        let end: u16 = parts[1].parse().context("year end")?;
        Ok((start..=end).collect())
    } else {
        s.split(',')
            .map(|y| y.trim().parse().context("year"))
            .collect()
    }
}

pub fn parse_since_days(s: &str) -> Result<u32> {
    if let Some(days) = s.strip_suffix('d') {
        days.parse().context("days")
    } else {
        s.parse().context("days")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_month_accepts_dash_form() {
        let m = parse_month("2026-05", false).unwrap();
        assert_eq!(m.year, 2026);
        assert_eq!(m.month, 5);
        assert_eq!(m.field, NvdMonthField::Published);
    }

    #[test]
    fn parse_month_accepts_compact_form() {
        let m = parse_month("202605", false).unwrap();
        assert_eq!(m.year, 2026);
        assert_eq!(m.month, 5);
    }

    #[test]
    fn parse_month_by_modified() {
        let m = parse_month("2026-05", true).unwrap();
        assert_eq!(m.field, NvdMonthField::Modified);
    }
}
