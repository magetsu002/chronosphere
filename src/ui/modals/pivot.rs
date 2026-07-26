use crate::app::{App, Modal, PivotEditField, PivotModalState};
use crate::ui::centered_rect;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let r = centered_rect(area, 80, 78);
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" pivots ", Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);

    let inner = block.inner(r);
    let modal = match &app.modal {
        Modal::Pivot(m) => m,
        _ => return,
    };

    match &modal.state {
        PivotModalState::List { cursor } => render_list(f, inner, app, *cursor),
        PivotModalState::Edit {
            fields, focused, ..
        } => render_edit(f, inner, fields, *focused),
    }
}

fn render_list(f: &mut Frame, area: Rect, app: &App, cursor: usize) {
    let eng = app.engagement.as_ref();
    let active_tunnel = eng.and_then(|e| e.pivots.active_tunnel.clone());
    let active_remote = eng.and_then(|e| e.pivots.active_remote.clone());
    let exec_mode = eng
        .map(|e| e.pivots.execution_mode.as_str())
        .unwrap_or("local");

    let items: Vec<ListItem> = eng
        .map(|e| e.pivots.pivots.clone())
        .unwrap_or_default()
        .iter()
        .map(|p| {
            let tun = if active_tunnel.as_deref() == Some(p.name.as_str()) {
                "T"
            } else {
                " "
            };
            let rem = if active_remote.as_deref() == Some(p.name.as_str()) {
                "R"
            } else {
                " "
            };
            let ssh = if p.has_ssh() { "ssh✓" } else { "ssh-" };
            let host = p.ssh_host.clone().unwrap_or_default();
            let label = format!(
                "{}{} {} {:>10}  {:<18}  {}",
                if tun == "T" || rem == "R" {
                    "● "
                } else {
                    "  "
                },
                tun,
                rem,
                p.name,
                host,
                ssh,
            );
            ListItem::new(Line::from(Span::styled(
                label,
                if tun == "T" || rem == "R" {
                    Theme::accent_bold()
                } else {
                    Theme::accent()
                },
            )))
        })
        .collect();

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(cursor.min(items.len().saturating_sub(1))));
    }
    let list = List::new(items)
        .highlight_style(Theme::selected())
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, layout[0], &mut state);

    let hints = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("exec:", Theme::magenta()),
            Span::raw(format!(" {}  ", exec_mode)),
            Span::styled("a", Theme::magenta()),
            Span::raw(" add  "),
            Span::styled("e", Theme::magenta()),
            Span::raw(" edit  "),
            Span::styled("d", Theme::magenta()),
            Span::raw(" delete  "),
            Span::styled("Enter", Theme::magenta()),
            Span::raw(" tunnel+remote  "),
            Span::styled("t/r", Theme::magenta()),
            Span::raw(" tunnel/remote only"),
        ]),
        Line::from(vec![
            Span::styled(":exec local|remote", Theme::warn()),
            Span::raw("  toggles script execution mode  "),
            Span::styled("Esc", Theme::magenta()),
            Span::raw(" close"),
        ]),
    ])
    .style(Theme::muted());
    f.render_widget(hints, layout[1]);
}

fn render_edit(f: &mut Frame, area: Rect, fields: &[(PivotEditField, String)], focused: usize) {
    let lines: Vec<Line> = fields
        .iter()
        .enumerate()
        .map(|(i, (field, val))| {
            let label = format!(" {:<14} ", field.label());
            let style = if i == focused {
                Theme::selected()
            } else {
                Theme::accent()
            };
            Line::from(vec![
                Span::styled(label, Theme::magenta()),
                Span::styled(val.clone(), style),
                Span::raw(if i == focused { "_" } else { "" }),
            ])
        })
        .collect();

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" edit pivot ", Theme::accent_bold()))
            .border_style(Theme::border_active())
            .style(Theme::panel()),
    );
    f.render_widget(p, area);
}
