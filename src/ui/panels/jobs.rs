use crate::app::{App, Focus};
use crate::engagement::JobStatus;
use crate::ui::layout::ListRegion;
use crate::ui::theme::Theme;
use chrono::Utc;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

pub fn render(f: &mut Frame, area: Rect, app: &App, hit: &mut ListRegion) {
    hit.panel = area;
    hit.list_inner = ListRegion::block_inner(area);
    let is_focused = app.focus == Focus::Jobs;
    let border_style = if is_focused {
        Theme::border_active()
    } else {
        Theme::border()
    };

    let title = if is_focused {
        format!(
            " jobs ({} running) — Enter/L log ",
            app.jobs_running_count()
        )
    } else {
        format!(" jobs ({} running) ", app.jobs_running_count())
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(title, Theme::accent_bold()))
        .border_style(border_style)
        .style(Theme::panel());

    let recent = app.jobs_last_n(50);
    let items: Vec<ListItem> = recent
        .iter()
        .rev()
        .map(|job| {
            let (icon, style) = match job.status {
                JobStatus::Running => ("●", Theme::accent()),
                JobStatus::Completed => ("✓", Theme::success()),
                JobStatus::Failed => ("✗", Theme::error()),
                JobStatus::Killed => ("✗", Theme::warn()),
                JobStatus::Unknown => ("?", Theme::muted()),
            };
            let elapsed = match job.finished_at {
                Some(f) => f - job.started_at,
                None => Utc::now() - job.started_at,
            };
            let elapsed_str = format_duration(elapsed.num_seconds());
            let line = Line::from(vec![
                Span::styled(icon.to_string(), style),
                Span::raw(" "),
                Span::styled(
                    job.command_title.chars().take(36).collect::<String>(),
                    Style::default(),
                ),
                Span::raw(" "),
                Span::styled(elapsed_str, Theme::muted()),
            ]);
            ListItem::new(line)
        })
        .collect();

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.selected_job.min(items.len() - 1)));
    }
    let list = List::new(items)
        .block(block)
        .highlight_style(Theme::selected())
        .highlight_symbol(if is_focused { "▶ " } else { "  " });
    f.render_stateful_widget(list, area, &mut state);
    hit.list_offset = state.offset();
}

fn format_duration(secs: i64) -> String {
    if secs < 0 {
        return "?".into();
    }
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs / 60) % 60)
    }
}
