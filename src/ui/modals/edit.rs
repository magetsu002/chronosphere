use crate::app::{App, Modal};
use crate::ui::centered_rect;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let r = centered_rect(area, 80, 55);
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" edit before running ", Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);
    let inner = block.inner(r);

    let modal = match &app.modal {
        Modal::Edit(m) => m,
        _ => return,
    };

    let show_suggestions = !modal.path_suggestions.is_empty();
    let sugg_rows = if show_suggestions {
        (modal.path_suggestions.len().min(6) as u16).max(3)
    } else {
        0
    };

    let mut constraints = vec![Constraint::Min(3), Constraint::Length(2)];
    if show_suggestions {
        constraints.insert(1, Constraint::Length(sugg_rows + 2));
    }
    if modal.save_as_prompt.is_some() {
        constraints.push(Constraint::Length(1));
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let mut idx = 0;
    f.render_widget(&modal.textarea, layout[idx]);
    idx += 1;

    if show_suggestions {
        let sugg_block = Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " path completions (Tab/Shift-Tab) ",
                Theme::accent_bold(),
            ))
            .border_style(Theme::border())
            .style(Theme::panel());
        let items: Vec<ListItem> = modal
            .path_suggestions
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let style = if i == modal.path_pick {
                    Theme::selected()
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(p.clone(), style)))
            })
            .collect();
        let mut state = ListState::default();
        state.select(Some(modal.path_pick.min(items.len().saturating_sub(1))));
        let list = List::new(items).block(sugg_block).highlight_symbol("▶ ");
        f.render_stateful_widget(list, layout[idx], &mut state);
        idx += 1;
    }

    let hints = Paragraph::new(Line::from(vec![
        Span::styled("Tab", Theme::magenta()),
        Span::raw(" path  "),
        Span::styled("Ctrl-H/U/W", Theme::magenta()),
        Span::raw(" delete  "),
        Span::styled("Ctrl-S", Theme::magenta()),
        Span::raw(" run  "),
        Span::styled("Ctrl-Shift-W", Theme::magenta()),
        Span::raw(" save  "),
        Span::styled("Esc", Theme::magenta()),
        Span::raw(" cancel"),
    ]))
    .style(Theme::muted());
    f.render_widget(hints, layout[idx]);
    idx += 1;

    if let Some(prompt) = &modal.save_as_prompt {
        let line = Paragraph::new(Line::from(vec![
            Span::styled(" save as id: ", Theme::accent_bold()),
            Span::styled(prompt.clone(), Theme::accent_bold()),
            Span::styled("_", Theme::accent_bold()),
        ]))
        .style(Theme::panel());
        f.render_widget(line, layout[idx]);
    }
}
