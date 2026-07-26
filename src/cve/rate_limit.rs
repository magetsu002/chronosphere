use anyhow::{Context, Result, bail};
use reqwest::header::{ACCEPT_ENCODING, HeaderMap, HeaderValue, RETRY_AFTER, USER_AGENT};
use reqwest::{Client, Response, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;

const MAX_RETRIES: u32 = 5;
const DEFAULT_RETRY_AFTER_SECS: u64 = 30;

static SYNC_SEMAPHORE: Semaphore = Semaphore::const_new(1);

pub struct SyncGuard {
    _permit: tokio::sync::SemaphorePermit<'static>,
}

pub async fn acquire_sync_lock() -> Result<SyncGuard> {
    let permit = SYNC_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| anyhow::anyhow!("sync lock closed"))?;
    Ok(SyncGuard { _permit: permit })
}

pub struct HttpClient {
    inner: Client,
    limiters: Arc<Mutex<HashMap<String, ProviderLimiter>>>,
}

#[derive(Debug)]
struct ProviderLimiter {
    min_interval: Duration,
    last_request: Option<Instant>,
    backoff_until: Option<Instant>,
}

impl HttpClient {
    pub fn new(user_agent: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(user_agent).context("invalid user agent")?,
        );
        let inner = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(120))
            .gzip(true)
            .build()?;
        Ok(Self {
            inner,
            limiters: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn inner(&self) -> &Client {
        &self.inner
    }

    pub async fn register_provider(&self, name: &str, min_interval_ms: u64) {
        let mut map = self.limiters.lock().await;
        map.insert(
            name.to_string(),
            ProviderLimiter {
                min_interval: Duration::from_millis(min_interval_ms),
                last_request: None,
                backoff_until: None,
            },
        );
    }

    async fn wait_for_slot(&self, provider: &str) {
        loop {
            let wait = {
                let mut map = self.limiters.lock().await;
                let limiter = map
                    .entry(provider.to_string())
                    .or_insert_with(|| ProviderLimiter {
                        min_interval: Duration::from_millis(1000),
                        last_request: None,
                        backoff_until: None,
                    });

                let now = Instant::now();
                if let Some(until) = limiter.backoff_until {
                    if now < until {
                        Some(until - now)
                    } else {
                        limiter.backoff_until = None;
                        None
                    }
                } else {
                    None
                }
                .or_else(|| {
                    limiter.last_request.and_then(|last| {
                        let elapsed = now.duration_since(last);
                        if elapsed < limiter.min_interval {
                            Some(limiter.min_interval - elapsed)
                        } else {
                            None
                        }
                    })
                })
            };
            if let Some(d) = wait {
                sleep(d).await;
            } else {
                break;
            }
        }
    }

    async fn mark_request(&self, provider: &str) {
        let mut map = self.limiters.lock().await;
        if let Some(l) = map.get_mut(provider) {
            l.last_request = Some(Instant::now());
        }
    }

    async fn set_backoff(&self, provider: &str, dur: Duration) {
        let mut map = self.limiters.lock().await;
        if let Some(l) = map.get_mut(provider) {
            l.backoff_until = Some(Instant::now() + dur);
        }
    }

    pub async fn get(&self, provider: &str, url: &str) -> Result<Response> {
        self.execute(provider, url, || self.inner.get(url)).await
    }

    pub async fn get_with_api_key(
        &self,
        provider: &str,
        url: &str,
        api_key: &str,
    ) -> Result<Response> {
        self.execute(provider, url, || {
            self.inner.get(url).header("apiKey", api_key)
        })
        .await
    }

    /// Read a successful HTTP response body as text, with a proxy-safe identity-encoding retry.
    pub async fn read_text(
        &self,
        provider: &str,
        url: &str,
        resp: Response,
        api_key: Option<&str>,
    ) -> Result<String> {
        let status = resp.status();
        match resp.text().await {
            Ok(text) => Ok(text),
            Err(first) => {
                tracing::warn!(url, error = %first, "response body decode failed, retrying without compression");
                let resp = self
                    .execute(provider, url, || {
                        let req = self.inner.get(url).header(ACCEPT_ENCODING, "identity");
                        if let Some(key) = api_key {
                            req.header("apiKey", key)
                        } else {
                            req
                        }
                    })
                    .await?;
                resp.text().await.with_context(|| {
                    format!(
                        "read response body from {url} (HTTP {status}) after decode error: {first}. \
                         This usually means a truncated or garbled response through a proxy — not NVD rate limiting \
                         (429 responses are retried automatically). Try without proxychains or set NVD_API_KEY."
                    )
                })
            }
        }
    }

    /// GET and return the response body as text.
    pub async fn get_text(&self, provider: &str, url: &str) -> Result<String> {
        let resp = self.get(provider, url).await?;
        self.read_text(provider, url, resp, None).await
    }

    /// GET with an API key and return the response body as text.
    pub async fn get_text_with_api_key(
        &self,
        provider: &str,
        url: &str,
        api_key: &str,
    ) -> Result<String> {
        let resp = self.get_with_api_key(provider, url, api_key).await?;
        self.read_text(provider, url, resp, Some(api_key)).await
    }

    /// GET and return the response body as bytes (for gzip feeds).
    pub async fn get_bytes(&self, provider: &str, url: &str) -> Result<Vec<u8>> {
        let resp = self.get(provider, url).await?;
        self.read_bytes(provider, url, resp).await
    }

    /// Read a successful HTTP response body as bytes, with an identity-encoding retry.
    pub async fn read_bytes(&self, provider: &str, url: &str, resp: Response) -> Result<Vec<u8>> {
        let status = resp.status();
        match resp.bytes().await {
            Ok(bytes) => Ok(bytes.to_vec()),
            Err(first) => {
                tracing::warn!(url, error = %first, "response body decode failed, retrying without compression");
                let resp = self
                    .execute(provider, url, || {
                        self.inner.get(url).header(ACCEPT_ENCODING, "identity")
                    })
                    .await?;
                let bytes = resp.bytes().await.with_context(|| {
                    format!(
                        "read response body from {url} (HTTP {status}) after decode error: {first}. \
                         This usually means a truncated or garbled response through a proxy."
                    )
                })?;
                Ok(bytes.to_vec())
            }
        }
    }

    async fn execute<F>(&self, provider: &str, url: &str, build: F) -> Result<Response>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        let mut attempt = 0u32;
        loop {
            self.wait_for_slot(provider).await;
            self.mark_request(provider).await;
            let resp = build()
                .send()
                .await
                .with_context(|| format!("{provider}: request to {url}"))?;

            let status = resp.status();
            if status.is_success() {
                return Ok(resp);
            }

            if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE
            {
                attempt += 1;
                if attempt >= MAX_RETRIES {
                    bail!(
                        "{provider}: rate limited after {MAX_RETRIES} retries (HTTP {status}) for {url}. \
                         Set NVD_API_KEY or wait before retrying."
                    );
                }
                let retry_secs = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(DEFAULT_RETRY_AFTER_SECS);
                tracing::warn!(
                    provider,
                    attempt,
                    retry_secs,
                    url,
                    "rate limited, backing off"
                );
                self.set_backoff(provider, Duration::from_secs(retry_secs))
                    .await;
                sleep(Duration::from_secs(retry_secs)).await;
                continue;
            }

            let body = resp.text().await.unwrap_or_default();
            let body_hint = truncate_body_hint(&body);
            let hint = http_error_hint(status, url);
            bail!("HTTP {status} for {url}{body_hint}{hint}");
        }
    }
}

fn truncate_body_hint(body: &str) -> String {
    let trimmed: String = body.chars().filter(|c| !c.is_control()).take(200).collect();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!(": {trimmed}")
    }
}

fn http_error_hint(status: StatusCode, url: &str) -> &'static str {
    match status {
        StatusCode::NOT_FOUND => {
            if url.contains("/feeds/json/cve/") {
                " (feed file not found — check the feed name; year feeds require `cve sync --full --years YYYY`)"
            } else {
                " (resource not found)"
            }
        }
        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => {
            " (likely rate limited — set NVD_API_KEY)"
        }
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limiter_enforces_interval() {
        let client = HttpClient::new("test/1.0").unwrap();
        client.register_provider("test", 100).await;
        let t0 = Instant::now();
        client.wait_for_slot("test").await;
        client.mark_request("test").await;
        client.wait_for_slot("test").await;
        assert!(t0.elapsed() >= Duration::from_millis(90));
    }
}
