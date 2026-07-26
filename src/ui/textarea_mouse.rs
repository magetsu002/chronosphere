use ratatui::layout::Rect;
use tui_textarea::{CursorMove, TextArea};

fn next_scroll_top(prev_top: u16, cursor: u16, len: u16) -> u16 {
    if cursor < prev_top {
        cursor
    } else if cursor >= prev_top.saturating_add(len) {
        cursor.saturating_sub(len.saturating_sub(1))
    } else {
        prev_top
    }
}

fn num_digits_usize(i: usize) -> u16 {
    if i == 0 { 1 } else { i.ilog10() as u16 + 1 }
}

/// Mirror `tui_textarea` viewport scroll after a frame (see `widget.rs`).
pub fn textarea_scroll_after_render(
    ta: &TextArea<'_>,
    prev: (u16, u16),
    inner_width: u16,
    inner_height: u16,
) -> (u16, u16) {
    let top_row = next_scroll_top(prev.0, ta.cursor().0 as u16, inner_height);
    let mut cursor_col = ta.cursor().1 as u16;
    if ta.line_number_style().is_some() {
        let lnum = num_digits_usize(ta.lines().len()) + 2;
        if cursor_col <= lnum {
            cursor_col *= 2;
        } else {
            cursor_col += lnum;
        }
    }
    let top_col = next_scroll_top(prev.1, cursor_col, inner_width);
    (top_row, top_col)
}

/// Move the textarea cursor to a terminal cell inside `area`.
pub fn textarea_cursor_from_click(
    ta: &mut TextArea<'static>,
    area: Rect,
    scroll: (u16, u16),
    column: u16,
    row: u16,
) -> bool {
    let inner = if ta.block().is_some() {
        crate::ui::layout::ListRegion::block_inner(area)
    } else {
        area
    };
    if column < inner.x
        || column >= inner.x.saturating_add(inner.width)
        || row < inner.y
        || row >= inner.y.saturating_add(inner.height)
    {
        return false;
    }

    let lnum = if ta.line_number_style().is_some() {
        num_digits_usize(ta.lines().len()) + 2
    } else {
        0
    };

    let rel_y = row.saturating_sub(inner.y);
    let rel_x = column.saturating_sub(inner.x);
    let line_count = ta.lines().len();
    if line_count == 0 {
        ta.move_cursor(CursorMove::Jump(0, 0));
        return true;
    }

    let line = (scroll.0.saturating_add(rel_y) as usize).min(line_count - 1);
    let mut text_col = rel_x.saturating_sub(lnum) as usize + scroll.1 as usize;
    let line_len = ta.lines().get(line).map(|l| l.chars().count()).unwrap_or(0);
    text_col = text_col.min(line_len);

    ta.move_cursor(CursorMove::Jump(line as u16, text_col as u16));
    true
}
