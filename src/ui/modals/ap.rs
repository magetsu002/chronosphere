use crate::app::{ApEditField, ApModalState, App, Modal};
use crate::ui::centered_rect;
use crate::ui::layout::ListRegion;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &App, list_hit: &mut Option<ListRegion>) {
    let r = centered_rect(area, 75, 75);
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" access points ", Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);

    let inner = block.inner(r);
    let modal = match &app.modal {
        Modal::Ap(m) => m,
        _ => return,
    };

    match &modal.state {
        ApModalState::List { cursor } => render_list(f, inner, app, *cursor, list_hit),
        ApModalState::Edit {
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
    cursor: usize,
    list_hit: &mut Option<ListRegion>,
) {
    let items: Vec<ListItem> = app
        .engagement
        .as_ref()
        .map(|e| e.aps.aps.clone())
        .unwrap_or_default()
        .iter()
        .map(|a| {
            let is_active = app
                .engagement
                .as_ref()
                .and_then(|e| e.aps.active.clone())
                .as_deref()
                == Some(&a.name);
            let ssid = a.ssid.clone().unwrap_or_default();
            let bssid = a.bssid.clone().unwrap_or_default();
            let psk = if a.wpa_psk.as_deref().is_some_and(|s| !s.is_empty()) {
                "psk✓"
            } else {
                "-"
            };
            let label = format!(
                "{}{:>10}  {:<22}  {:<18}  {}",
                if is_active { "● " } else { "  " },
                a.name,
                ssid,
                bssid,
                psk,
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

fn render_edit(f: &mut Frame, area: Rect, fields: &[(ApEditField, String)], focused: usize) {
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

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" edit AP ", Theme::accent_bold()))
            .border_style(Theme::border_active())
            .style(Theme::panel()),
    );
    f.render_widget(p, area);
}
