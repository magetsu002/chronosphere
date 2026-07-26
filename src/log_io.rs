use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

pub const DEFAULT_TAIL_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_GREP_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 16 * 1024;

#[derive(Debug, Serialize)]
pub struct TailOutput {
    pub lines: Vec<String>,
    pub total_lines: Option<usize>,
    pub file_bytes: u64,
    pub scanned_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct LogMatch {
    pub line: usize,
    pub text: String,
    pub line_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct GrepOutput {
    pub matches: Vec<LogMatch>,
    pub scanned_bytes: u64,
    pub truncated: bool,
}

pub fn tail_lines(path: &Path, max_lines: usize, max_bytes: u64) -> Result<TailOutput> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let file_bytes = file.metadata()?.len();
    let start = file_bytes.saturating_sub(max_bytes.max(1));
    let total_lines = if start == 0 {
        Some(count_lines(path)?)
    } else {
        None
    };
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::new(file);
    if start > 0 {
        discard_partial_line(&mut reader)?;
    }

    let mut lines = VecDeque::with_capacity(max_lines.min(5000));
    let mut scanned_bytes = 0u64;
    while let Some(line) = read_bounded_line(&mut reader, MAX_LINE_BYTES, u64::MAX)? {
        scanned_bytes = scanned_bytes.saturating_add(line.bytes_consumed);
        if lines.len() == max_lines {
            lines.pop_front();
        }
        lines.push_back(line.text);
    }

    Ok(TailOutput {
        lines: lines.into_iter().collect(),
        total_lines,
        file_bytes,
        scanned_bytes,
        truncated: start > 0,
    })
}

pub fn grep_lines(
    path: &Path,
    pattern: &str,
    ignore_case: bool,
    max_matches: usize,
    max_bytes: u64,
) -> Result<GrepOutput> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let needle = if ignore_case {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };
    let mut scanned_bytes = 0u64;
    let mut line_number = 0usize;
    let mut matches = Vec::new();
    let mut truncated = false;

    while scanned_bytes < max_bytes {
        let remaining = max_bytes - scanned_bytes;
        let Some(line) = read_bounded_line(&mut reader, MAX_LINE_BYTES, remaining)? else {
            break;
        };
        scanned_bytes = scanned_bytes.saturating_add(line.bytes_consumed);
        line_number += 1;
        let haystack = if ignore_case {
            line.text.to_lowercase()
        } else {
            line.text.clone()
        };
        if haystack.contains(&needle) {
            matches.push(LogMatch {
                line: line_number,
                text: line.text,
                line_truncated: line.output_truncated,
            });
            if matches.len() >= max_matches {
                truncated = true;
                break;
            }
        }
        if line.scan_limit_reached {
            truncated = true;
            break;
        }
    }

    if scanned_bytes >= max_bytes {
        truncated = true;
    }
    Ok(GrepOutput {
        matches,
        scanned_bytes,
        truncated,
    })
}

struct BoundedLine {
    text: String,
    bytes_consumed: u64,
    output_truncated: bool,
    scan_limit_reached: bool,
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_output_bytes: usize,
    max_scan_bytes: u64,
) -> std::io::Result<Option<BoundedLine>> {
    let mut output = Vec::with_capacity(max_output_bytes.min(4096));
    let mut consumed = 0u64;
    let mut output_truncated = false;
    let mut saw_any = false;
    let mut scan_limit_reached = false;

    loop {
        if consumed >= max_scan_bytes {
            scan_limit_reached = true;
            break;
        }
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        let buffer_len = buffer.len();
        saw_any = true;
        let allowed = usize::try_from((max_scan_bytes - consumed).min(usize::MAX as u64))
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let slice = &buffer[..allowed];
        let newline = slice.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(slice.len(), |index| index + 1);
        let remaining_output = max_output_bytes.saturating_sub(output.len());
        let copy = take.min(remaining_output);
        output.extend_from_slice(&slice[..copy]);
        output_truncated |= copy < take;
        reader.consume(take);
        consumed += take as u64;
        if newline.is_some() {
            break;
        }
        if take == allowed && allowed < buffer_len {
            scan_limit_reached = true;
            break;
        }
    }

    if !saw_any {
        return Ok(None);
    }
    while output
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        output.pop();
    }
    Ok(Some(BoundedLine {
        text: String::from_utf8_lossy(&output).into_owned(),
        bytes_consumed: consumed,
        output_truncated,
        scan_limit_reached,
    }))
}

fn discard_partial_line<R: BufRead>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(());
        }
        if let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
            reader.consume(index + 1);
            return Ok(());
        }
        let len = buffer.len();
        reader.consume(len);
    }
}

fn count_lines(path: &Path) -> Result<usize> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buffer = [0u8; 64 * 1024];
    let mut count = 0usize;
    let mut last = None;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += buffer[..read].iter().filter(|byte| **byte == b'\n').count();
        last = buffer.get(read - 1).copied();
    }
    if last.is_some_and(|byte| byte != b'\n') {
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn tails_large_logs_with_bounded_memory_window() {
        let dir = std::env::temp_dir().join(format!("chrono-log-tail-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("large.log");
        let mut file = File::create(&path).unwrap();
        for index in 0..100_000usize {
            writeln!(file, "line-{index:06}-{}", "x".repeat(32)).unwrap();
        }
        let result = tail_lines(&path, 25, 64 * 1024).unwrap();
        assert_eq!(result.lines.len(), 25);
        assert!(result.lines.last().unwrap().starts_with("line-099999"));
        assert!(result.truncated);
        assert!(result.scanned_bytes <= 64 * 1024);
        assert_eq!(result.total_lines, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn streams_grep_and_caps_matches_and_bytes() {
        let dir = std::env::temp_dir().join(format!("chrono-log-grep-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("large.log");
        let mut file = File::create(&path).unwrap();
        for index in 0..20_000usize {
            let marker = if index % 100 == 0 { " needle" } else { "" };
            writeln!(file, "row-{index:06}{marker}").unwrap();
        }
        let result = grep_lines(&path, "needle", true, 10, 4 * 1024 * 1024).unwrap();
        assert_eq!(result.matches.len(), 10);
        assert!(result.truncated);
        assert!(result.scanned_bytes <= 4 * 1024 * 1024);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn truncates_single_oversized_lines_without_unbounded_output() {
        let dir = std::env::temp_dir().join(format!("chrono-log-line-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oversized.log");
        std::fs::write(
            &path,
            format!("needle-{}\n", "x".repeat(MAX_LINE_BYTES * 4)),
        )
        .unwrap();
        let result = grep_lines(&path, "needle", false, 5, 8 * 1024 * 1024).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert!(result.matches[0].line_truncated);
        assert!(result.matches[0].text.len() <= MAX_LINE_BYTES);
        let _ = std::fs::remove_dir_all(dir);
    }
}
