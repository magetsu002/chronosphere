use crate::app::{App, Modal};
use crate::ui::centered_rect;
use crate::ui::layout::{EditHitRegions, ListRegion, ScrollRegion};
use crate::ui::textarea_mouse::textarea_scroll_after_render;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

pub fn render(f: &mut Frame, area: Rect, app: &mut App, edit_hit: &mut Option<EditHitRegions>) {
    *edit_hit = None;

    let r = centered_rect(area, 80, 55);
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" edit before running ", Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);
    let inner = block.inner(r);

    let modal = match &mut app.modal {
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

    let textarea_area = layout[0];
    let inner_block = modal.textarea.block().cloned();
    let (inner_w, inner_h) = if let Some(b) = inner_block.as_ref() {
        let inner = b.inner(textarea_area);
        (inner.width, inner.height)
    } else {
        (textarea_area.width, textarea_area.height)
    };
    modal.textarea_scroll =
        textarea_scroll_after_render(&modal.textarea, modal.textarea_scroll, inner_w, inner_h);

    let mut idx = 0;
    f.render_widget(&modal.textarea, layout[idx]);
    let mut suggestions = None;
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
        suggestions = Some(ListRegion {
            panel: layout[idx],
            list_inner: ListRegion::block_inner(layout[idx]),
            list_offset: state.offset(),
        });
        idx += 1;
    }

    let hints = Paragraph::new(Line::from(vec![
        Span::styled("click", Theme::magenta()),
        Span::raw(" place cursor  "),
        Span::styled("wheel", Theme::magenta()),
        Span::raw(" scroll  "),
        Span::styled("Tab", Theme::magenta()),
        Span::raw(" path  "),
        Span::styled("Ctrl-S", Theme::magenta()),
        Span::raw(" run  "),
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

    *edit_hit = Some(EditHitRegions {
        textarea_panel: textarea_area,
        textarea: ScrollRegion::from_block(textarea_area),
        suggestions,
    });
}
