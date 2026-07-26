use crate::app::{App, Modal, TargetEditField, TargetModal, TargetModalState};
use crate::ui::centered_rect;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let r = centered_rect(area, 70, 70);
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" targets ", Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);

    let inner = block.inner(r);
    let modal = match &app.modal {
        Modal::Target(m) => m,
        _ => return,
    };

    match &modal.state {
        TargetModalState::List { cursor } => render_list(f, inner, app, modal, *cursor),
        TargetModalState::Edit {
            fields, focused, ..
        } => render_edit(f, inner, fields, *focused),
    }

    let _ = TargetModal::default;
}

fn render_list(f: &mut Frame, area: Rect, app: &App, _modal: &TargetModal, cursor: usize) {
    let items: Vec<ListItem> = app
        .engagement
        .as_ref()
        .map(|e| e.targets.targets.clone())
        .unwrap_or_default()
        .iter()
        .map(|t| {
            let is_active = app
                .engagement
                .as_ref()
                .and_then(|e| e.targets.active.clone())
                .as_deref()
                == Some(&t.name);
            let ip = t.ip.clone().unwrap_or_default();
            let host = t.hostname.clone().unwrap_or_default();
            let lhost = t.lhost.clone().unwrap_or_default();
            let lport = t.lport.map(|p| p.to_string()).unwrap_or_default();
            let label = format!(
                "{}{:>12}  {:<20}  {:<24}  lhost={:<14}  lport={}",
                if is_active { "● " } else { "  " },
                t.name,
                ip,
                host,
                lhost,
                lport
            );
            ListItem::new(Line::from(Span::styled(
                label,
                if is_active {
                    Theme::accent_bold()
                } else {
                    Theme::accent()
                },
            )))
        })
        .collect();

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(2)])
        .split(area);

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(cursor.min(items.len().saturating_sub(1))));
    }
    let list = List::new(items)
        .highlight_style(Theme::selected())
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, layout[0], &mut state);

    let hints = Paragraph::new(Line::from(vec![
        Span::styled("a", Theme::magenta()),
        Span::raw(" add  "),
        Span::styled("e", Theme::magenta()),
        Span::raw(" edit  "),
        Span::styled("d", Theme::magenta()),
        Span::raw(" delete  "),
        Span::styled("Enter", Theme::magenta()),
        Span::raw(" set active  "),
        Span::styled("L", Theme::magenta()),
        Span::raw(" detect tun0 for active  "),
        Span::styled("Esc", Theme::magenta()),
        Span::raw(" close"),
    ]))
    .style(Theme::muted());
    f.render_widget(hints, layout[1]);
}

fn render_edit(f: &mut Frame, area: Rect, fields: &[(TargetEditField, String)], focused: usize) {
    let lines: Vec<Line> = fields
        .iter()
        .enumerate()
        .map(|(i, (field, val))| {
            let label = format!(" {:<10} ", field.label());
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

    let hints = Line::from(vec![
        Span::styled("Tab", Theme::magenta()),
        Span::raw(" next  "),
        Span::styled("Shift-Tab", Theme::magenta()),
        Span::raw(" prev  "),
        Span::styled("Ctrl-H/U/W", Theme::magenta()),
        Span::raw(" delete  "),
        Span::styled("Enter", Theme::magenta()),
        Span::raw(" save  "),
        Span::styled("Esc", Theme::magenta()),
        Span::raw(" cancel"),
    ]);

    let mut all_lines = vec![Line::from(Span::styled(
        "edit target".to_string(),
        Theme::accent_bold(),
    ))];
    all_lines.push(Line::from(""));
    all_lines.extend(lines);
    all_lines.push(Line::from(""));
    all_lines.push(hints);

    let p = Paragraph::new(all_lines).style(Theme::panel());
    f.render_widget(p, area);
}
