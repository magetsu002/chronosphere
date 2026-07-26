use crate::config;
use anyhow::{Context, Result};
use base64::Engine;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Default)]
pub struct CopyReport {
    pub system_clipboard: bool,
    /// tmux automatic paste buffer (prefix `]` in a normal pane — not inside Chronosphere).
    pub tmux_buffer: bool,
    /// OSC 52 — copies to your **terminal app's** clipboard (works over SSH on iTerm2, Ghostty, etc.).
    pub terminal_clipboard: bool,
    pub file_path: Option<PathBuf>,
}

impl CopyReport {
    pub fn any(&self) -> bool {
        self.system_clipboard
            || self.tmux_buffer
            || self.terminal_clipboard
            || self.file_path.is_some()
    }
}

pub fn last_yank_path() -> PathBuf {
    config::data_dir().join("last_yank.txt")
}

pub fn format_yank_message(r: &CopyReport) -> String {
    let mut parts = Vec::new();
    if r.terminal_clipboard {
        parts.push("terminal clipboard (Cmd/Ctrl+V here)");
    }
    if r.system_clipboard {
        parts.push("Kali desktop clipboard");
    }
    if r.tmux_buffer {
        parts.push("tmux buffer");
    }

    let file_hint = r.file_path.as_ref().map(|p| format!("cat {}", p.display()));

    let paste_hint = if r.tmux_buffer {
        "paste: open another tmux pane, then Ctrl-b ] (won't work inside Chronosphere)"
    } else if r.terminal_clipboard {
        "paste: Cmd/Ctrl+V in this terminal"
    } else if r.system_clipboard {
        "paste: Shift+Insert in a normal shell on Kali (not your laptop if SSH)"
    } else {
        ""
    };

    match (parts.is_empty(), file_hint) {
        (true, Some(path)) => format!("yanked → file only — {path}"),
        (false, Some(path)) if paste_hint.is_empty() => {
            format!("yanked → {} — also {path}", parts.join(" + "))
        }
        (false, Some(path)) => format!(
            "yanked → {} — {paste_hint} — fallback: {path}",
            parts.join(" + ")
        ),
        (false, None) if !paste_hint.is_empty() => {
            format!("yanked → {} — {paste_hint}", parts.join(" + "))
        }
        (false, None) => format!("yanked → {}", parts.join(" + ")),
        (true, None) => "yank failed — no clipboard backend".to_string(),
    }
}

fn tmux_available() -> bool {
    which::which("tmux").is_ok()
}

fn pipe_to_command(cmd: &mut Command, text: &str) -> Result<bool> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn clipboard command")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes()).context("write stdin")?;
    }
    Ok(child.wait().context("wait clipboard command")?.success())
}

/// tmux **automatic** paste buffer (what prefix `]` / `paste-buffer` uses). Do NOT use `-b` or `-w`.
fn copy_to_tmux_paste_buffer(text: &str) -> Result<()> {
    if !tmux_available() {
        anyhow::bail!("tmux not in PATH");
    }

    // load-buffer without -b → top automatic buffer (see tmux(1) load-buffer).
    let tmp = std::env::temp_dir().join(format!("chronosphere-yank-{}.txt", std::process::id()));
    std::fs::write(&tmp, text).context("write temp yank file")?;
    let loaded = Command::new("tmux")
        .args(["load-buffer", tmp.to_str().context("temp path utf8")?])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&tmp);

    if loaded {
        return Ok(());
    }

    if !pipe_to_command(&mut Command::new("tmux").args(["set-buffer", "-"]), text)? {
        anyhow::bail!("tmux set-buffer failed");
    }
    Ok(())
}

/// OSC 52: ask the terminal emulator to place text on the **local** clipboard (SSH-friendly).
fn copy_terminal_osc52(text: &str) -> bool {
    const MAX_BYTES: usize = 48_000;
    if text.len() > MAX_BYTES {
        return false;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    let seq = format!("\x1b]52;c;{b64}\x07");
    std::io::stderr()
        .write_all(seq.as_bytes())
        .and_then(|_| std::io::stderr().flush())
        .is_ok()
}

#[cfg(target_os = "linux")]
fn linux_clipboard_env_available() -> bool {
    std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok()
}

#[cfg(target_os = "linux")]
fn copy_system_clipboard_linux(text: &str) -> bool {
    if !linux_clipboard_env_available() {
        return false;
    }
    if which::which("xclip").is_ok() {
        for sel in ["clipboard", "primary"] {
            if pipe_to_command(&mut Command::new("xclip").args(["-selection", sel]), text)
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    if which::which("xsel").is_ok() {
        for sel in ["--clipboard", "--primary"] {
            if pipe_to_command(&mut Command::new("xsel").arg(sel), text).unwrap_or(false) {
                return true;
            }
        }
    }
    if which::which("wl-copy").is_ok() {
        if pipe_to_command(&mut Command::new("wl-copy"), text).unwrap_or(false) {
            return true;
        }
    }
    // tmux can push to system clipboard when linked with X11/Wayland.
    if tmux_available() {
        if pipe_to_command(
            &mut Command::new("tmux").args(["set-buffer", "-w", "-"]),
            text,
        )
        .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn copy_system_clipboard(text: &str) -> bool {
    #[cfg(target_os = "linux")]
    if !linux_clipboard_env_available() {
        return false;
    }
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if cb.set_text(text.to_string()).is_ok() {
            return true;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if copy_system_clipboard_linux(text) {
            return true;
        }
    }
    false
}

fn save_last_yank_file(text: &str) -> Result<PathBuf> {
    let path = last_yank_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, text).context("write last_yank.txt")?;
    Ok(path)
}

pub fn copy(text: &str) -> Result<()> {
    let r = copy_report(text)?;
    if r.any() {
        Ok(())
    } else {
        anyhow::bail!("no clipboard backend available")
    }
}

pub fn copy_report(text: &str) -> Result<CopyReport> {
    let mut r = CopyReport::default();

    if copy_terminal_osc52(text) {
        r.terminal_clipboard = true;
    }

    if copy_system_clipboard(text) {
        r.system_clipboard = true;
    }

    if tmux_available() {
        if copy_to_tmux_paste_buffer(text).is_ok() {
            r.tmux_buffer = true;
        }
    }

    // Last-resort: always write file so user can `cat … | bash` or paste from editor.
    match save_last_yank_file(text) {
        Ok(p) => r.file_path = Some(p),
        Err(err) => tracing::warn!(?err, "could not write last_yank.txt"),
    }

    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_message_includes_tmux_paste_hint() {
        let msg = format_yank_message(&CopyReport {
            tmux_buffer: true,
            ..Default::default()
        });
        assert!(msg.contains("tmux"));
        assert!(msg.contains("Ctrl-b ]"));
    }
}
