use crate::app::{App, JobLogModal, Modal};
use crate::engagement::JobRecord;
use crate::exec::tmux;
use crate::ui::centered_rect;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};

pub fn max_scroll(modal: &JobLogModal, visible_lines: usize) -> usize {
    modal.lines.len().saturating_sub(visible_lines.max(1))
}

pub fn clamp_scroll(modal: &mut JobLogModal, visible_lines: usize) {
    let max = max_scroll(modal, visible_lines);
    if modal.follow {
        modal.scroll = max;
    } else {
        modal.scroll = modal.scroll.min(max);
    }
}

/// Full read (modal just opened or log was truncated).
pub fn load_log_lines(job: &JobRecord) -> Vec<String> {
    match job.log_path.as_ref() {
        Some(p) if p.exists() => match fs::read_to_string(p) {
            Ok(body) if body.is_empty() => vec!["(log file is empty)".to_string()],
            Ok(body) => body.lines().map(normalize_display_line).collect(),
            Err(err) => vec![format!("(failed to read log: {})", err)],
        },
        Some(p) => vec![format!("(log not found: {})", p.display())],
        None => vec!["(no log path for this job)".to_string()],
    }
}

/// Incrementally append new bytes from the job log file.
pub fn refresh_modal_from_job(modal: &mut JobLogModal, job: &JobRecord) {
    modal.title = job.command_title.clone();
    modal.status = job.status;
    modal.exit_code = job.exit_code;

    if let Some(wid) = job.tmux_window.as_deref() {
        // Prefer tmux capture when available: shows exactly what the job's window shows,
        // including interactive progress output.
        if tmux::has_tmux() {
            if let Ok(lines) = tmux::capture_pane(wid, -5000) {
                modal.lines = lines;
                modal.read_offset = 0;
                modal.pending_line.clear();
                return;
            }
        }
    }

    let Some(path) = job.log_path.as_ref() else {
        modal.lines = vec!["(no log path for this job)".to_string()];
        modal.read_offset = 0;
        modal.pending_line.clear();
        return;
    };

    if !path.exists() {
        if modal.lines.is_empty() {
            modal.lines = vec![format!("(waiting for log: {})", path.display())];
        }
        return;
    }

    let file_len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    if file_len < modal.read_offset {
        modal.read_offset = 0;
        modal.pending_line.clear();
        modal.lines.clear();
    }

    if modal.read_offset == 0 && modal.lines.is_empty() {
        modal.lines = load_log_lines(job);
        modal.read_offset = file_len;
        modal.pending_line.clear();
        return;
    }

    if file_len <= modal.read_offset {
        return;
    }

    let Ok(mut file) = File::open(path) else {
        return;
    };
    if file.seek(SeekFrom::Start(modal.read_offset)).is_err() {
        return;
    }

    let mut chunk = Vec::new();
    if file.read_to_end(&mut chunk).is_err() {
        return;
    }
    modal.read_offset = file_len;

    let text = String::from_utf8_lossy(&chunk);
    append_chunk(modal, &text);
}

fn append_chunk(modal: &mut JobLogModal, chunk: &str) {
    if !chunk.contains('\n') {
        if chunk.contains('\r') {
            push_line(modal, chunk);
            return;
        }
        modal.pending_line.push_str(chunk);
        return;
    }

    let combined = format!("{}{}", modal.pending_line, chunk);
    let ends_with_newline = combined.ends_with('\n');

    let mut parts: Vec<&str> = combined.split('\n').collect();
    if !ends_with_newline {
        if let Some(tail) = parts.pop() {
            modal.pending_line = tail.to_string();
        } else {
            modal.pending_line.clear();
        }
    } else {
        modal.pending_line.clear();
    }

    if parts.is_empty() {
        return;
    }

    if modal.lines.len() == 1 && is_placeholder_line(&modal.lines[0]) {
        modal.lines.clear();
    }

    for line in parts {
        push_line(modal, line);
    }
}

fn push_line(modal: &mut JobLogModal, raw: &str) {
    let display = normalize_display_line(raw);
    if display.is_empty() {
        return;
    }
    // ffuf and similar tools overwrite the same terminal row with \r — update in place.
    if raw.contains('\r') {
        if let Some(last) = modal.lines.last_mut() {
            *last = display;
        } else {
            modal.lines.push(display);
        }
        return;
    }
    modal.lines.push(display);
}

fn is_placeholder_line(s: &str) -> bool {
    s.starts_with('(') && s.ends_with(')')
}

fn normalize_display_line(s: &str) -> String {
    if s.contains('\r') {
        s.rsplit('\r')
            .find(|part| !part.is_empty())
            .unwrap_or("")
            .to_string()
    } else {
        s.to_string()
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let Modal::JobLog(modal) = &mut app.modal else {
        return;
    };

    let popup = centered_rect(area, 88, 85);
    f.render_widget(Clear, popup);

    let status_label = format!("{:?}", modal.status).to_lowercase();
    let backend = if app
        .jobs
        .iter()
        .find(|j| j.id == modal.job_id)
        .and_then(|j| j.tmux_window.as_ref())
        .is_some()
        && tmux::has_tmux()
    {
        "tmux"
    } else {
        "log"
    };
    let follow = if modal.follow { "follow" } else { "scroll" };
    let title = format!(
        " job: {}  [{}]  {}  {}{} ",
        truncate(&modal.title, 40),
        status_label,
        backend,
        follow,
        modal
            .exit_code
            .map(|c| format!("  exit={c}"))
            .unwrap_or_default()
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(title, Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), popup);
    let inner = block.inner(popup);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(inner);

    let visible_lines = layout[0].height.max(1) as usize;
    modal.last_visible_lines = visible_lines;

    if let Some(job) = app.jobs.iter().find(|j| j.id == modal.job_id) {
        refresh_modal_from_job(modal, job);
    }
    clamp_scroll(modal, visible_lines);

    let width = layout[0].width.max(1) as usize;
    let body: Vec<Line> = modal
        .lines
        .iter()
        .skip(modal.scroll)
        .take(visible_lines)
        .map(|line| Line::from(truncate(line, width)))
        .collect();

    let paragraph = if body.is_empty() {
        let msg = if modal.lines.is_empty() {
            "(no output yet — log updates while the job runs)"
        } else {
            "(end of scrollable output)"
        };
        Paragraph::new(Line::from(Span::styled(msg, Theme::muted())))
    } else {
        Paragraph::new(body).style(Style::default())
    };
    f.render_widget(paragraph.wrap(Wrap { trim: false }), layout[0]);

    let position = if modal.lines.is_empty() {
        "0/0".to_string()
    } else {
        let end = (modal.scroll + visible_lines).min(modal.lines.len());
        format!("{}/{} lines", end, modal.lines.len())
    };

    let hints = Line::from(vec![
        Span::styled(" j/k ", Theme::magenta()),
        Span::raw("scroll  "),
        Span::styled("Ctrl-d/u", Theme::magenta()),
        Span::raw(" page  "),
        Span::styled("g/G", Theme::magenta()),
        Span::raw(" top/bottom  "),
        Span::styled("f", Theme::magenta()),
        Span::raw(" follow  "),
        Span::styled("o", Theme::magenta()),
        Span::raw(" tmux  "),
        Span::styled("Esc", Theme::magenta()),
        Span::raw(" close  "),
        Span::styled(position, Theme::muted().add_modifier(Modifier::ITALIC)),
    ]);
    f.render_widget(Paragraph::new(hints).style(Theme::muted()), layout[1]);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::JobLogModal;
    use crate::engagement::JobStatus;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_log(contents: &[u8]) -> (std::path::PathBuf, JobRecord) {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("chrono-job-log-{n}.log"));
        std::fs::write(&path, contents).unwrap();
        let job = JobRecord {
            id: "j1".into(),
            command_id: None,
            command_title: "scan".into(),
            resolved: "ffuf".into(),
            started_at: chrono::Utc::now(),
            finished_at: None,
            status: JobStatus::Running,
            exit_code: None,
            tmux_window: None,
            log_path: Some(path.clone()),
            target: None,
            profile: None,
            ap: None,
            pivot: None,
            execution: None,
        };
        (path, job)
    }

    #[test]
    fn follow_mode_scrolls_to_bottom() {
        let mut modal = JobLogModal {
            job_id: "j".into(),
            title: "scan".into(),
            status: JobStatus::Running,
            exit_code: None,
            lines: (1..=20).map(|i| format!("line{i}")).collect(),
            scroll: 0,
            follow: true,
            read_offset: 0,
            pending_line: String::new(),
            last_visible_lines: 10,
        };
        clamp_scroll(&mut modal, 10);
        assert_eq!(modal.scroll, 10);
    }

    #[test]
    fn manual_scroll_clamped() {
        let mut modal = JobLogModal {
            job_id: "j".into(),
            title: "scan".into(),
            status: JobStatus::Completed,
            exit_code: Some(0),
            lines: vec!["a".into(), "b".into(), "c".into()],
            scroll: 99,
            follow: false,
            read_offset: 0,
            pending_line: String::new(),
            last_visible_lines: 2,
        };
        clamp_scroll(&mut modal, 2);
        assert_eq!(modal.scroll, 1);
    }

    #[test]
    fn incremental_tail_appends_new_lines() {
        let (path, job) = temp_log(b"line1\n");
        let mut modal = JobLogModal {
            job_id: job.id.clone(),
            title: job.command_title.clone(),
            status: JobStatus::Running,
            exit_code: None,
            lines: Vec::new(),
            scroll: 0,
            follow: true,
            read_offset: 0,
            pending_line: String::new(),
            last_visible_lines: 10,
        };
        refresh_modal_from_job(&mut modal, &job);
        assert_eq!(modal.lines, vec!["line1"]);

        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"line2\n")
            .unwrap();
        refresh_modal_from_job(&mut modal, &job);
        assert_eq!(modal.lines, vec!["line1", "line2"]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn carriage_return_updates_last_line() {
        let mut modal = JobLogModal {
            job_id: "j".into(),
            title: "scan".into(),
            status: JobStatus::Running,
            exit_code: None,
            lines: vec!["progress 10%".into()],
            scroll: 0,
            follow: true,
            read_offset: 0,
            pending_line: String::new(),
            last_visible_lines: 10,
        };
        append_chunk(&mut modal, "progress 50%\r");
        assert_eq!(modal.lines.len(), 1);
        assert_eq!(modal.lines[0], "progress 50%");
    }
}
