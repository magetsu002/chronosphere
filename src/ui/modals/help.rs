use crate::app::{App, HelpModal, Modal};
use crate::ui::centered_rect;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

const HELP: &[(&str, &str)] = &[
    ("h / l", "focus left / right panel"),
    ("j / k", "move down / up"),
    ("gg / G", "top / bottom"),
    ("Ctrl-d / Ctrl-u", "half-page down / up"),
    (
        "Enter / r",
        "run highlighted command in background tmux window",
    ),
    ("Nr (e.g. 5r)", "run command N times in parallel"),
    ("space", "toggle multi-select on highlighted command"),
    ("R", "run all multi-selected (or all visible in category)"),
    (
        "y / Y",
        "yank — paste in another tmux pane: Ctrl-b ]; or cat ~/.local/share/chronosphere/last_yank.txt",
    ),
    ("e", "inline edit the resolved command before running"),
    ("Tab", "filesystem path completion (in editor)"),
    ("o", "focus the active job's tmux window"),
    ("Enter / L", "floating job log (jobs panel)"),
    ("]j / [j", "next / previous job"),
    ("dj", "kill the active job"),
    (".", "repeat last action"),
    ("/", "fuzzy search within current category"),
    ("g/", "fuzzy search across all commands"),
    (":", "command palette"),
    ("? / :help", "show this help"),
    ("Esc / Ctrl-c", "clear selection / dismiss modal"),
    ("q / :q", "quit"),
    ("", ""),
    (
        "job log (floating)",
        "j/k scroll  Ctrl-d/u page  g/G top/bottom  f follow  o tmux",
    ),
    ("", ""),
    (":engagement", "list/switch/new engagement"),
    (":target", "list/edit/switch active host target"),
    (":ap", "list/edit/switch active WiFi access point"),
    (
        ":pivot",
        "list/edit foothold pivots; tunnel (T) + remote (R) markers",
    ),
    (
        ":exec local|remote",
        "run commands locally or via scp+ssh on remote pivot (all commands allowed in remote mode)",
    ),
    (":creds", "list/edit/switch active credential profile"),
    (
        ":variable",
        "template vars (iface, wordlist, …) — globals; WiFi fields live on :ap",
    ),
    (
        ":variable name=value",
        "quick-set one variable from the command palette",
    ),
    (":tools", "show which referenced tools are on $PATH"),
    (":reload", "force-reload command library from disk"),
    (
        ":cve",
        "browse/search local CVE index (s sync, K KEV filter)",
    ),
    (
        ":write",
        "save inline-edited command as new id in engagement overrides",
    ),
];

pub fn help_line_count() -> usize {
    HELP.len() + 4
}

pub fn max_scroll(_modal: &HelpModal, visible_lines: usize) -> usize {
    help_line_count().saturating_sub(visible_lines.max(1))
}

pub fn clamp_scroll(modal: &mut HelpModal, visible_lines: usize) {
    modal.scroll = modal.scroll.min(max_scroll(modal, visible_lines));
}

fn help_lines() -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::with_capacity(HELP.len() + 4);
    lines.push(Line::from(Span::styled(
        "chronosphere — vim keymap".to_string(),
        Theme::accent_bold(),
    )));
    lines.push(Line::from(""));
    for (k, d) in HELP {
        if k.is_empty() && d.is_empty() {
            lines.push(Line::from(""));
            continue;
        }
        lines.push(Line::from(vec![
            Span::styled(format!("  {:<18}", k), Theme::magenta()),
            Span::raw(" "),
            Span::raw(d.to_string()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "scroll with j/k — Esc or ? to close".to_string(),
        Theme::muted(),
    )));
    lines
}

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let Modal::Help(modal) = &mut app.modal else {
        return;
    };

    let r = centered_rect(area, 70, 80);
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" help ", Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);
    let inner = block.inner(r);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(inner);

    let visible_lines = layout[0].height.max(1) as usize;
    modal.last_visible_lines = visible_lines;
    clamp_scroll(modal, visible_lines);

    let lines = help_lines();
    let p = Paragraph::new(lines)
        .block(Block::default())
        .wrap(Wrap { trim: false })
        .scroll((modal.scroll as u16, 0));
    f.render_widget(p, layout[0]);

    let end = (modal.scroll + visible_lines).min(help_line_count());
    let position = format!("{}/{} lines", end, help_line_count());
    let hints = Line::from(vec![
        Span::styled(" j/k ", Theme::magenta()),
        Span::raw("scroll  "),
        Span::styled("Ctrl-d/u", Theme::magenta()),
        Span::raw(" page  "),
        Span::styled("g/G", Theme::magenta()),
        Span::raw(" top/bottom  "),
        Span::styled("Esc/?", Theme::magenta()),
        Span::raw(" close  "),
        Span::styled(position, Theme::muted().add_modifier(Modifier::ITALIC)),
    ]);
    f.render_widget(Paragraph::new(hints).style(Theme::muted()), layout[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_scroll_respects_viewport() {
        let mut modal = HelpModal {
            scroll: 999,
            last_visible_lines: 10,
        };
        clamp_scroll(&mut modal, 10);
        assert_eq!(modal.scroll, max_scroll(&modal, 10));
    }
}
