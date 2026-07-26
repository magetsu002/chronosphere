use crate::app::{App, Focus};
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let is_focused = app.focus == Focus::Categories;
    let border_style = if is_focused {
        Theme::border_active()
    } else {
        Theme::border()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" categories ", Theme::accent_bold()))
        .border_style(border_style)
        .style(Theme::panel());

    let items: Vec<ListItem> = app
        .library
        .categories
        .iter()
        .map(|c| {
            let count = c
                .commands
                .iter()
                .filter(|cmd| app.command_is_applicable(cmd))
                .count();
            let count_str = format!(" ({})", count);
            let line = Line::from(vec![
                Span::styled(
                    c.icon.as_deref().unwrap_or("").to_string(),
                    Theme::magenta(),
                ),
                Span::raw(" "),
                Span::styled(c.display_name.clone(), Style::default()),
                Span::styled(count_str, Theme::muted()),
            ]);
            ListItem::new(line)
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.selected_category));
    let list = List::new(items)
        .block(block)
        .highlight_style(Theme::selected())
        .highlight_symbol(if is_focused { "▶ " } else { "  " });
    f.render_stateful_widget(list, area, &mut state);
}
