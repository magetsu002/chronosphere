use crate::engagement::{ApStore, Engagement, PivotStore, ProfileStore, VariableStore};
use crate::render::RenderContext;
use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn is_sensitive_key(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    normalized.contains("password")
        || normalized.contains("passwd")
        || normalized.contains("secret")
        || normalized.contains("token")
        || normalized.contains("api_key")
        || normalized.contains("apikey")
        || normalized.contains("private_key")
        || normalized.contains("nt_hash")
        || normalized.contains("ntlm_hash")
        || normalized.contains("wpa_psk")
        || normalized.contains("wps_pin")
        || normalized.ends_with("_key")
}

fn add_secret(values: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        values.push(value.to_string());
    }
}

pub fn context_secrets(ctx: &RenderContext) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(profile) = &ctx.profile {
        add_secret(&mut values, profile.password.as_deref());
        add_secret(&mut values, profile.nt_hash.as_deref());
    }
    if let Some(ap) = &ctx.ap {
        add_secret(&mut values, ap.wpa_psk.as_deref());
        add_secret(&mut values, ap.wps_pin.as_deref());
    }
    for pivot in [ctx.pivot_tunnel.as_ref(), ctx.pivot_remote.as_ref()]
        .into_iter()
        .flatten()
    {
        add_secret(&mut values, pivot.ssh_password.as_deref());
    }
    for (name, value) in &ctx.globals {
        if is_sensitive_key(name) {
            add_secret(&mut values, Some(value));
        }
    }
    normalize_secrets(values)
}

pub fn store_secrets(
    profiles: &ProfileStore,
    aps: &ApStore,
    pivots: &PivotStore,
    variables: &VariableStore,
) -> Vec<String> {
    let mut values = Vec::new();
    for profile in &profiles.profiles {
        add_secret(&mut values, profile.password.as_deref());
        add_secret(&mut values, profile.nt_hash.as_deref());
    }
    for ap in &aps.aps {
        add_secret(&mut values, ap.wpa_psk.as_deref());
        add_secret(&mut values, ap.wps_pin.as_deref());
    }
    for pivot in &pivots.pivots {
        add_secret(&mut values, pivot.ssh_password.as_deref());
    }
    for (name, value) in &variables.values {
        if is_sensitive_key(name) {
            add_secret(&mut values, Some(value));
        }
    }
    normalize_secrets(values)
}

fn normalize_secrets(mut values: Vec<String>) -> Vec<String> {
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    values.dedup();
    values
}

pub fn redact_values(text: &str, secrets: &[String]) -> String {
    let mut redacted = text.to_string();
    let mut ordered = secrets.to_vec();
    ordered.sort_by_key(|value| std::cmp::Reverse(value.len()));
    ordered.dedup();
    for secret in ordered {
        if !secret.is_empty() {
            redacted = redacted.replace(&secret, "<redacted>");
        }
    }
    redacted
}

pub fn redact_command(text: &str, ctx: &RenderContext) -> String {
    redact_values(text, &context_secrets(ctx))
}

pub fn redact_for_engagement(text: &str, engagement: &Engagement) -> String {
    redact_values(
        text,
        &store_secrets(
            &engagement.profiles,
            &engagement.aps,
            &engagement.pivots,
            &engagement.variables,
        ),
    )
}

pub fn create_private_file(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open private file {}", path.display()))?;
    secure_existing_file(path)?;
    Ok(file)
}

pub fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create directory {}", parent.display()))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("chronosphere-state");
    let temporary = parent.join(format!(".{filename}.{}.tmp", uuid::Uuid::new_v4()));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create temporary file {}", temporary.display()))?;
    file.write_all(contents)
        .with_context(|| format!("write temporary file {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("sync temporary file {}", temporary.display()))?;
    drop(file);

    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("replace {}", path.display()))?;
    }

    fs::rename(&temporary, path)
        .with_context(|| format!("replace {} atomically", path.display()))?;
    secure_existing_file(path)?;
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

pub fn secure_existing_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("protect {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_longest_values_first() {
        let text = "password=secret and secret-suffix";
        let values = vec!["secret".to_string(), "secret-suffix".to_string()];
        assert_eq!(
            redact_values(text, &values),
            "password=<redacted> and <redacted>"
        );
    }

    #[test]
    fn recognizes_secret_variable_names() {
        assert!(is_sensitive_key("api_token"));
        assert!(is_sensitive_key("client_private_key"));
        assert!(!is_sensitive_key("wordlist"));
    }
}
