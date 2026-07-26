//! Filesystem path completion for the inline command editor.

use directories::UserDirs;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathToken {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

/// Token under the cursor (whitespace- or quote-delimited).
pub fn token_at_cursor(line: &str, cursor_col: usize) -> Option<PathToken> {
    if line.is_empty() {
        return None;
    }
    let cursor_col = cursor_col.min(line.len());
    let is_boundary = |c: char| c.is_whitespace() || c == '\'' || c == '"';
    let mut start = cursor_col;
    while start > 0 {
        let prev = line[..start].chars().next_back()?;
        if is_boundary(prev) {
            break;
        }
        start -= prev.len_utf8();
    }
    let mut end = cursor_col;
    while end < line.len() {
        let next = line[end..].chars().next()?;
        if is_boundary(next) {
            break;
        }
        end += next.len_utf8();
    }
    if start == end {
        return None;
    }
    Some(PathToken {
        start,
        end,
        text: line[start..end].to_string(),
    })
}

/// Whether this token should offer filesystem completion.
pub fn looks_like_path(token: &str, line: &str, token_start: usize) -> bool {
    if token.starts_with('/')
        || token.starts_with("./")
        || token.starts_with("../")
        || token.starts_with('~')
        || token.contains('/')
    {
        return true;
    }
    let before = line[..token_start].trim_end();
    if before.ends_with('=') {
        return true;
    }
    const FLAGS_WITH_SPACE: &[&str] = &["-w ", "-W ", "-f ", "-o ", "-F ", "-d ", "-i "];
    for flag in FLAGS_WITH_SPACE {
        if before.ends_with(flag) {
            return true;
        }
    }
    const FLAGS_BARE: &[&str] = &["-w", "-W", "-f", "-o", "-F", "-d", "-i"];
    for flag in FLAGS_BARE {
        let Some(i) = before.rfind(flag) else {
            continue;
        };
        let after = i + flag.len();
        if after >= before.len() {
            return true;
        }
        if before.as_bytes().get(after) == Some(&b' ') {
            return true;
        }
    }
    const FLAGS_EQ: &[&str] = &["--wordlist=", "--output=", "--log-file=", "--outfile="];
    for flag in FLAGS_EQ {
        if before.ends_with(flag) {
            return true;
        }
    }
    false
}

/// List completion strings (full token replacements).
pub fn completions(token: &str, extra_roots: &[PathBuf]) -> Vec<String> {
    let (search_dir, prefix, rebuild_prefix) = split_token(token, extra_roots);
    let show_hidden = prefix.starts_with('.');
    let mut names = list_matching_entries(&search_dir, &prefix, show_hidden);
    if names.is_empty()
        && !extra_roots.is_empty()
        && !token.contains('/')
        && !token.starts_with('~')
    {
        for root in extra_roots {
            if !root.is_dir() {
                continue;
            }
            names = list_matching_entries(root, &prefix, show_hidden);
            if !names.is_empty() {
                return names
                    .into_iter()
                    .map(|name| join_display_path(&root.display().to_string(), &name))
                    .collect();
            }
        }
        return Vec::new();
    }
    names
        .into_iter()
        .map(|name| join_display_path(&rebuild_prefix, &name))
        .collect()
}

pub fn longest_common_prefix(strings: &[String]) -> String {
    if strings.is_empty() {
        return String::new();
    }
    if strings.len() == 1 {
        return strings[0].clone();
    }
    let mut prefix = strings[0].clone();
    for s in &strings[1..] {
        while !s.starts_with(&prefix) {
            prefix.pop();
            if prefix.is_empty() {
                return String::new();
            }
        }
    }
    prefix
}

pub fn replace_token(
    textarea: &mut tui_textarea::TextArea<'static>,
    line_idx: usize,
    start: usize,
    end: usize,
    replacement: &str,
) {
    let block = textarea.block().cloned();
    let line_number_style = textarea.line_number_style();
    let cursor_style = textarea.cursor_style();
    let tab_length = textarea.tab_length();

    let mut lines: Vec<String> = textarea.lines().to_vec();
    if line_idx >= lines.len() {
        return;
    }
    let current = &lines[line_idx];
    if start > current.len() || end > current.len() || start > end {
        return;
    }
    lines[line_idx] = format!("{}{}{}", &current[..start], replacement, &current[end..]);

    let mut ta = tui_textarea::TextArea::new(lines);
    if let Some(style) = line_number_style {
        ta.set_line_number_style(style);
    }
    ta.set_cursor_style(cursor_style);
    ta.set_tab_length(tab_length);
    if let Some(b) = block {
        ta.set_block(b);
    }
    let new_col =
        (start + replacement.len()).min(ta.lines().get(line_idx).map(|l| l.len()).unwrap_or(0));
    ta.move_cursor(tui_textarea::CursorMove::Jump(
        line_idx as u16,
        new_col as u16,
    ));
    *textarea = ta;
}

fn split_token(token: &str, extra_roots: &[PathBuf]) -> (PathBuf, String, String) {
    if token.is_empty() {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        return (cwd, String::new(), String::new());
    }

    if token.ends_with('/') {
        let expanded = expand_tilde(token);
        let dir = PathBuf::from(&expanded);
        let display = token.to_string();
        return (dir, String::new(), display);
    }

    let expanded = expand_tilde(token);
    let path = Path::new(&expanded);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_prefix = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();

    let parent_path = if parent.as_os_str().is_empty() {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        parent.to_path_buf()
    };

    let rebuild_prefix = if token.starts_with("~/") {
        let home = home_dir();
        let rel = strip_home_prefix(parent_path.as_path(), home.as_path());
        if let Some(rel) = rel {
            if rel.as_os_str().is_empty() {
                "~/".to_string()
            } else {
                format!("~/{}", rel.display())
            }
        } else {
            token
                .rfind('/')
                .map(|i| token[..=i].to_string())
                .unwrap_or_else(|| "~/".to_string())
        }
    } else if token.starts_with('/') {
        token
            .rfind('/')
            .map(|i| token[..=i].to_string())
            .unwrap_or_default()
    } else if token.contains('/') {
        token
            .rfind('/')
            .map(|i| token[..=i].to_string())
            .unwrap_or_default()
    } else {
        // Bare filename after a flag — search extra roots first, then cwd.
        if extra_roots.iter().any(|r| r.is_dir()) {
            return (parent_path, file_prefix, String::new());
        }
        String::new()
    };

    (parent_path, file_prefix, rebuild_prefix)
}

fn expand_tilde(token: &str) -> String {
    if token == "~" {
        return home_dir().display().to_string();
    }
    if let Some(rest) = token.strip_prefix("~/") {
        return home_dir().join(rest).display().to_string();
    }
    token.to_string()
}

fn home_dir() -> PathBuf {
    UserDirs::new()
        .map(|u| u.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn strip_home_prefix<'a>(path: &'a Path, home: &Path) -> Option<PathBuf> {
    if path.starts_with(home) {
        Some(path.strip_prefix(home).ok()?.to_path_buf())
    } else {
        None
    }
}

fn list_matching_entries(dir: &Path, prefix: &str, show_hidden: bool) -> Vec<String> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in read.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if !prefix.is_empty() && !name.starts_with(prefix) {
            continue;
        }
        if name.starts_with('.') && !show_hidden && prefix.is_empty() {
            continue;
        }
        let mut display = name;
        if ent.path().is_dir() {
            display.push('/');
        }
        out.push(display);
    }
    out.sort_by(|a, b| a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()));
    out
}

fn join_display_path(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else if prefix.ends_with('/') {
        format!("{prefix}{name}")
    } else {
        format!("{prefix}/{name}")
    }
}

pub fn completion_roots(engagement_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(e) = engagement_dir {
        let wl = e.join("wordlists");
        if wl.is_dir() {
            roots.push(wl);
        }
    }
    for p in [
        "/usr/share/wordlists",
        "/usr/share/seclists",
        "/opt/wordlists",
    ] {
        let pb = PathBuf::from(p);
        if pb.is_dir() {
            roots.push(pb);
        }
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_at_cursor_mid_word() {
        let line = "hashcat -m 22000 /usr/share/wordlists/ro";
        let t = token_at_cursor(line, line.len()).unwrap();
        assert_eq!(t.text, "/usr/share/wordlists/ro");
        assert!(looks_like_path(&t.text, line, t.start));
    }

    #[test]
    fn looks_like_path_slash() {
        assert!(looks_like_path("/usr/share", "cmd /usr/share", 4));
    }

    #[test]
    fn looks_like_path_after_flag() {
        assert!(looks_like_path(
            "rockyou.txt",
            "feroxbuster -w rockyou.txt",
            15
        ));
        assert!(looks_like_path("rock", "feroxbuster -w rock", 15));
        assert!(looks_like_path("you", "feroxbuster -w rockyou.txt", 22));
    }

    #[test]
    fn lcp_works() {
        let v = vec![
            "/usr/share/wordlists/rockyou.txt".into(),
            "/usr/share/wordlists/rockyou-small.txt".into(),
        ];
        assert_eq!(longest_common_prefix(&v), "/usr/share/wordlists/rockyou");
    }
}
