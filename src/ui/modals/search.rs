use crate::app::{App, Modal};
use crate::ui::centered_rect;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let r = centered_rect(area, 80, 70);
    f.render_widget(Clear, r);
    let global = matches!(app.mode, crate::vim::Mode::SearchGlobal);
    let title = if global {
        " search: all "
    } else {
        " search: current category "
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(title, Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);
    let inner = block.inner(r);

    let modal = match &app.modal {
        Modal::Search { matches, cursor } => (matches, cursor),
        _ => return,
    };

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(3)])
        .split(inner);

    let prompt_line = Line::from(vec![
        Span::styled(if global { "g/" } else { "/" }, Theme::accent_bold()),
        Span::styled(app.search_buf.clone(), Theme::accent_bold()),
        Span::styled("_", Theme::accent_bold()),
    ]);
    f.render_widget(Paragraph::new(prompt_line).style(Theme::panel()), layout[0]);

    let items: Vec<ListItem> = modal
        .0
        .iter()
        .map(|m| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{}] ", m.category_name), Theme::magenta()),
                Span::raw(m.title.clone()),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some((*modal.1).min(items.len() - 1)));
    }
    let list = List::new(items)
        .highlight_style(Theme::selected())
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, layout[1], &mut state);
}
