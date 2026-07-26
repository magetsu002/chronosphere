use crate::app::{App, CredEditField, CredsModal, CredsModalState, Modal};
use crate::ui::centered_rect;
use crate::ui::layout::ListRegion;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &App, list_hit: &mut Option<ListRegion>) {
    let r = centered_rect(area, 70, 70);
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" credentials ", Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);
    let inner = block.inner(r);

    let modal = match &app.modal {
        Modal::Creds(m) => m,
        _ => return,
    };

    match &modal.state {
        CredsModalState::List { cursor } => render_list(f, inner, app, modal, *cursor, list_hit),
        CredsModalState::Edit {
            fields, focused, ..
        } => {
            *list_hit = None;
            render_edit(f, inner, fields, *focused);
        }
    }
}

fn render_list(
    f: &mut Frame,
    area: Rect,
    app: &App,
    _modal: &CredsModal,
    cursor: usize,
    list_hit: &mut Option<ListRegion>,
) {
    let items: Vec<ListItem> = app
        .engagement
        .as_ref()
        .map(|e| e.profiles.profiles.clone())
        .unwrap_or_default()
        .iter()
        .map(|p| {
            let is_active = app
                .engagement
                .as_ref()
                .and_then(|e| e.profiles.active.clone())
                .as_deref()
                == Some(&p.name);
            let secret_repr = match p.kind {
                crate::engagement::CredKind::Plaintext => p
                    .password
                    .as_deref()
                    .map(|s| format!("{:.>4}", &s.chars().rev().take(4).collect::<String>()))
                    .unwrap_or_default(),
                crate::engagement::CredKind::Ntlm => p
                    .nt_hash
                    .as_deref()
                    .map(|s| format!("{}…", &s[..8.min(s.len())]))
                    .unwrap_or_default(),
                crate::engagement::CredKind::Kerberos => p.ticket_path.clone().unwrap_or_default(),
                crate::engagement::CredKind::None => "-".into(),
            };
            let label = format!(
                "{}{:<16} {:<14}\\{:<16} kind={:<9} secret={}",
                if is_active { "● " } else { "  " },
                p.name,
                p.domain.clone().unwrap_or_default(),
                p.username,
                p.kind.as_str(),
                secret_repr
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
    *list_hit = Some(ListRegion {
        panel: layout[0],
        list_inner: layout[0],
        list_offset: state.offset(),
    });

    let hints = Paragraph::new(Line::from(vec![
        Span::styled("a", Theme::magenta()),
        Span::raw(" add  "),
        Span::styled("e", Theme::magenta()),
        Span::raw(" edit  "),
        Span::styled("d", Theme::magenta()),
        Span::raw(" delete  "),
        Span::styled("Enter", Theme::magenta()),
        Span::raw(" set active  "),
        Span::styled("Esc", Theme::magenta()),
        Span::raw(" close"),
    ]))
    .style(Theme::muted());
    f.render_widget(hints, layout[1]);
}

fn render_edit(f: &mut Frame, area: Rect, fields: &[(CredEditField, String)], focused: usize) {
    let lines: Vec<Line> = fields
        .iter()
        .enumerate()
        .map(|(i, (field, val))| {
            let label = format!(" {:<12} ", field.label());
            let display = if matches!(field, CredEditField::Password | CredEditField::NtHash) {
                "*".repeat(val.len())
            } else {
                val.clone()
            };
            let style = if i == focused {
                Theme::selected()
            } else {
                Theme::accent()
            };
            Line::from(vec![
                Span::styled(label, Theme::magenta()),
                Span::styled(display, style),
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
        Span::raw(" cancel  "),
        Span::raw("(kind: plaintext / ntlm / kerberos / none)"),
    ]);

    let mut all_lines = vec![Line::from(Span::styled(
        "edit credential profile".to_string(),
        Theme::accent_bold(),
    ))];
    all_lines.push(Line::from(""));
    all_lines.extend(lines);
    all_lines.push(Line::from(""));
    all_lines.push(hints);

    let p = Paragraph::new(all_lines).style(Theme::panel());
    f.render_widget(p, area);
}
