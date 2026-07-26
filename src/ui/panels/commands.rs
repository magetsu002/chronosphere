use crate::app::{App, Focus};
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let is_focused = app.focus == Focus::Commands;
    let border_style = if is_focused {
        Theme::border_active()
    } else {
        Theme::border()
    };

    let title = match app.current_category() {
        Some(c) => format!(" {} ", c.display_name),
        None => " commands ".into(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(title, Theme::accent_bold()))
        .border_style(border_style)
        .style(Theme::panel());

    let visible = app.visible_commands();
    let items: Vec<ListItem> = visible
        .iter()
        .map(|cmd| {
            let interactive_tag = if cmd.interactive {
                Span::styled(" ◐ interactive", Theme::warn())
            } else {
                Span::raw("")
            };
            let tag_strs: Vec<Span> = cmd
                .tags
                .iter()
                .map(|t| Span::styled(format!(" #{}", t), Theme::muted()))
                .collect();
            let req_ok = cmd.requires.iter().all(|t| which::which(t).is_ok());
            let req_marker = if cmd.requires.is_empty() {
                Span::raw("")
            } else if req_ok {
                Span::styled(" ✓", Theme::success())
            } else {
                Span::styled(" ✗", Theme::error())
            };
            let selected_marker = if app.multi_selected_contains(&cmd.id) {
                Span::styled("● ", Theme::magenta().add_modifier(Modifier::BOLD))
            } else {
                Span::raw("  ")
            };

            let mut spans = vec![
                selected_marker,
                Span::styled(cmd.title.clone(), Style::default()),
                req_marker,
                interactive_tag,
            ];
            spans.extend(tag_strs.into_iter().take(4));
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    let selected = app
        .effective_command_index()
        .unwrap_or(0)
        .min(visible.len().saturating_sub(1));
    if !visible.is_empty() {
        state.select(Some(selected));
    }
    let list = List::new(items)
        .block(block)
        .highlight_style(Theme::selected())
        .highlight_symbol(if is_focused { "▶ " } else { "  " });
    f.render_stateful_widget(list, area, &mut state);
}
