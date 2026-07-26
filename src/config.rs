use directories::ProjectDirs;
use std::path::PathBuf;

pub const APP_QUALIFIER: &str = "dev";
pub const APP_ORG: &str = "chronosphere";
pub const APP_NAME: &str = "chronosphere";

pub fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME)
}

pub fn data_dir() -> PathBuf {
    project_dirs()
        .map(|d| d.data_local_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".chronosphere/data"))
}

pub fn config_dir() -> PathBuf {
    project_dirs()
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".chronosphere/config"))
}

pub fn log_file_path() -> PathBuf {
    data_dir().join("chronosphere.log")
}

pub fn engagements_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("engagements")
}

pub fn user_commands_dir() -> PathBuf {
    data_dir().join("commands")
}

/// Where chronosphere finds its built-in command library at runtime.
///
/// Resolution order:
///   1. `$CHRONOSPHERE_COMMANDS_DIR` if set and exists.
///   2. `$CARGO_MANIFEST_DIR/commands` if it exists (dev workflow).
///   3. `$XDG_DATA_HOME/chronosphere/commands` — populated from the embedded
///      copy on first run / version bump.
///   4. System paths: `/usr/local/share/chronosphere/commands`,
///      `/usr/share/chronosphere/commands`.
pub fn builtin_commands_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CHRONOSPHERE_COMMANDS_DIR") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return pb;
        }
    }
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("commands");
    if dev.exists() {
        return dev;
    }
    let user = user_commands_dir();
    if user.exists() {
        return user;
    }
    for sys in [
        "/usr/local/share/chronosphere/commands",
        "/usr/share/chronosphere/commands",
    ] {
        let p = PathBuf::from(sys);
        if p.exists() {
            return p;
        }
    }
    user
}

pub fn last_engagement_marker() -> PathBuf {
    data_dir().join("last_engagement")
}

pub fn cve_dir() -> PathBuf {
    data_dir().join("cve")
}

pub fn cve_db_path() -> PathBuf {
    cve_dir().join("cve.db")
}

pub fn cve_sync_state_path() -> PathBuf {
    cve_dir().join("sync-state.json")
}

pub fn cve_config_path() -> PathBuf {
    config_dir().join("cve.toml")
}

/// On-disk size of the CVE store (SQLite db + WAL/SHM sidecars + sync-state).
pub fn cve_storage_size_bytes() -> u64 {
    let dir = cve_dir();
    ["cve.db", "cve.db-wal", "cve.db-shm", "sync-state.json"]
        .iter()
        .map(|name| dir.join(name))
        .filter_map(|p| std::fs::metadata(&p).ok())
        .map(|m| m.len())
        .sum()
}

pub fn format_storage_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub const TMUX_SESSION: &str = "chronosphere";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_storage_size_scales() {
        assert_eq!(format_storage_size(512), "512 B");
        assert_eq!(format_storage_size(2048), "2.0 KB");
        assert_eq!(format_storage_size(5 * 1024 * 1024), "5.0 MB");
    }
}
