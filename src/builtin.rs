//! Built-in command library, embedded at compile time. On first run (or `chronosphere
//! update-templates`) we extract these into the user data dir so the binary is fully
//! portable — no need to ship the `commands/` directory alongside it.

use anyhow::{Context, Result};
use include_dir::{Dir, File, include_dir};
use std::fs;
use std::path::Path;

pub static EMBEDDED: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/commands");

fn collect_files<'a>(dir: &'a Dir<'a>, out: &mut Vec<&'a File<'a>>) {
    for f in dir.files() {
        if f.path().extension().and_then(|e| e.to_str()) == Some("toml") {
            out.push(f);
        }
    }
    for d in dir.dirs() {
        collect_files(d, out);
    }
}

/// Extract every embedded TOML into `dest`, creating the directory if needed.
/// If `overwrite` is false, existing files are left alone.
pub fn extract_to(dest: &Path, overwrite: bool) -> Result<usize> {
    fs::create_dir_all(dest).with_context(|| format!("create {}", dest.display()))?;
    let mut files = Vec::new();
    collect_files(&EMBEDDED, &mut files);
    let mut written = 0usize;
    for file in files {
        let rel = file.path();
        let out = dest.join(rel);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).ok();
        }
        if !overwrite && out.exists() {
            continue;
        }
        fs::write(&out, file.contents()).with_context(|| format!("write {}", out.display()))?;
        written += 1;
    }
    Ok(written)
}

/// Ensure the user data commands dir has been populated at least once.
/// Returns the populated path.
pub fn ensure_user_dir() -> Result<std::path::PathBuf> {
    let dir = crate::config::user_commands_dir();
    let stamp = dir.join(".chronosphere.version");
    let want = env!("CARGO_PKG_VERSION");
    let have = fs::read_to_string(&stamp).ok().unwrap_or_default();
    let needs_update = have.trim() != want;
    if !dir.exists() || needs_update {
        extract_to(&dir, needs_update)?;
        fs::write(&stamp, want).ok();
    }
    Ok(dir)
}
