use crate::app::{App, Modal, VariableEditField, VariablesModalState};
use crate::ui::centered_rect;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let r = centered_rect(area, 75, 75);
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" variables ", Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);

    let inner = block.inner(r);
    let modal = match &app.modal {
        Modal::Variables(m) => m,
        _ => return,
    };

    match &modal.state {
        VariablesModalState::List { cursor, unset_only } => {
            render_list(f, inner, app, *cursor, *unset_only)
        }
        VariablesModalState::Edit {
            name,
            value,
            focused,
            name_editable,
        } => render_edit(f, inner, name, value, *focused, *name_editable),
    }
}

fn render_list(f: &mut Frame, area: Rect, app: &App, cursor: usize, unset_only: bool) {
    let rows = app.variable_rows(unset_only);
    let (set_n, unset_n) = app.variable_counts();

    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| {
            let is_set = row.value.as_ref().is_some_and(|v| !v.is_empty());
            let status = if is_set { "set   " } else { "unset " };
            let val = row
                .value
                .as_deref()
                .filter(|v| !v.is_empty())
                .unwrap_or("—");
            let val_short = if val.len() > 42 {
                format!("{}…", &val[..41])
            } else {
                val.to_string()
            };
            let tag = if row.needed_by_current {
                " ◀cmd"
            } else if row.in_library {
                ""
            } else {
                " custom"
            };
            let style = if is_set {
                Theme::success()
            } else if row.needed_by_current {
                Theme::warn()
            } else {
                Theme::muted()
            };
            let label = format!("  {}  {:<18}  {}{}", status, row.name, val_short, tag);
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);

    let summary = Paragraph::new(Line::from(vec![
        Span::styled(format!("{} set", set_n), Theme::success()),
        Span::raw("  ·  "),
        Span::styled(format!("{} unset", unset_n), Theme::warn()),
        Span::raw("  ·  persisted in engagement "),
        Span::styled("variables.json", Theme::muted()),
    ]));
    f.render_widget(summary, layout[0]);

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(cursor.min(items.len().saturating_sub(1))));
    }
    let list = List::new(items)
        .highlight_style(Theme::selected())
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, layout[1], &mut state);

    let current_need = app.current_command_unresolved_vars();
    let need_line = if current_need.is_empty() {
        Line::from(Span::styled(
            "highlighted command: all template vars resolved".to_string(),
            Theme::muted(),
        ))
    } else {
        Line::from(vec![
            Span::styled("highlighted command needs: ", Theme::warn()),
            Span::styled(current_need.join(", "), Theme::warn()),
        ])
    };

    let hints = vec![
        need_line,
        Line::from(vec![
            Span::styled("a", Theme::magenta()),
            Span::raw(" add  "),
            Span::styled("e", Theme::magenta()),
            Span::raw(" edit  "),
            Span::styled("d", Theme::magenta()),
            Span::raw(" clear  "),
            Span::styled("u", Theme::magenta()),
            Span::raw(if unset_only {
                " show all  "
            } else {
                " unset only  "
            }),
            Span::styled("Tab", Theme::magenta()),
            Span::raw(" path complete (in editor)  "),
            Span::styled("Esc", Theme::magenta()),
            Span::raw(" close"),
        ]),
    ];
    let p = Paragraph::new(hints).style(Theme::muted());
    f.render_widget(p, layout[2]);
}

fn render_edit(
    f: &mut Frame,
    area: Rect,
    name: &str,
    value: &str,
    focused: usize,
    name_editable: bool,
) {
    let fields = [
        (VariableEditField::Name, name, name_editable),
        (VariableEditField::Value, value, true),
    ];
    let lines: Vec<Line> = fields
        .iter()
        .enumerate()
        .map(|(i, (field, val, editable))| {
            let style = if i == focused {
                Theme::selected()
            } else {
                Theme::accent()
            };
            let suffix = if i == focused && *editable { "_" } else { "" };
            let display = if *field == VariableEditField::Name && !editable {
                format!("{:<10} {}", field.label(), val)
            } else {
                format!("{:<10} {}{}", field.label(), val, suffix)
            };
            Line::from(Span::styled(display, style))
        })
        .collect();

    let hints = Line::from(vec![
        Span::styled("Tab", Theme::magenta()),
        Span::raw(" next  "),
        Span::styled("Enter", Theme::magenta()),
        Span::raw(" save  "),
        Span::styled("Esc", Theme::magenta()),
        Span::raw(" cancel"),
    ]);

    let mut all_lines = vec![Line::from(Span::styled(
        "edit variable".to_string(),
        Theme::accent_bold(),
    ))];
    all_lines.push(Line::from(""));
    all_lines.extend(lines);
    all_lines.push(Line::from(""));
    all_lines.push(hints);

    let p = Paragraph::new(all_lines).style(Theme::panel());
    f.render_widget(p, area);
}
