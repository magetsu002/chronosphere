use crate::app::{App, CveModal, Modal};
use crate::ui::centered_rect;
use crate::ui::layout::{ListRegion, ScrollRegion};
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

pub fn max_detail_scroll(modal: &CveModal, visible_lines: usize) -> usize {
    detail_line_count(modal).saturating_sub(visible_lines.max(1))
}

pub fn clamp_detail_scroll(modal: &mut CveModal, visible_lines: usize) {
    modal.detail_scroll = modal
        .detail_scroll
        .min(max_detail_scroll(modal, visible_lines));
}

fn detail_line_count(modal: &CveModal) -> usize {
    build_detail_lines(modal).len()
}

fn build_detail_lines(modal: &CveModal) -> Vec<Line<'static>> {
    let rec = match modal.detail_record.as_ref() {
        Some(r) => r,
        None => return vec![Line::from("No selection")],
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        rec.id.clone(),
        Theme::accent_bold(),
    )));
    if let Some(s) = &rec.severity {
        let cvss = rec
            .cvss_v31
            .map(|v| format!(" CVSS {v:.1}"))
            .unwrap_or_default();
        lines.push(Line::from(format!("{s}{cvss}")));
    }
    if rec.in_kev {
        lines.push(Line::from(Span::styled(
            format!(
                "KEV added {} due {}",
                rec.kev_date_added.as_deref().unwrap_or("-"),
                rec.kev_due_date.as_deref().unwrap_or("-"),
            ),
            Theme::warn(),
        )));
    }
    if let Some(poc) = crate::cve::poc_index::lookup(&rec.id) {
        let root = &crate::cve::PocIndex::global().root;
        lines.push(Line::from(Span::styled(
            format!(
                "Local PoC [{}] {}",
                poc.status,
                poc.absolute_path(root).display()
            ),
            Theme::accent_bold(),
        )));
        if let Some(id) = &poc.chronosphere_id {
            lines.push(Line::from(format!("run: chronosphere run {id}")));
        }
    }
    if let Some(e) = rec.epss_score {
        lines.push(Line::from(format!(
            "EPSS {:.4} (p{:.1}%)",
            e,
            rec.epss_percentile.unwrap_or(0.0) * 100.0
        )));
    }
    if !rec.products.is_empty() {
        let prods: String = rec
            .products
            .iter()
            .take(6)
            .map(|p| format!("{}/{}", p.vendor, p.product))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(Line::from(format!("Products: {prods}")));
    }
    if !rec.cwes.is_empty() {
        lines.push(Line::from(format!("CWEs: {}", rec.cwes.join(", "))));
    }
    lines.push(Line::from(""));
    for line in rec.description.lines() {
        lines.push(Line::from(line.to_string()));
    }
    if !rec.references.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("References:", Theme::muted())));
        for r in rec.references.iter().take(8) {
            lines.push(Line::from(format!("  {}", r.url)));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Esc back  j/k/wheel scroll  y yank id",
        Theme::muted(),
    )));
    lines
}

pub fn render(
    f: &mut Frame,
    area: Rect,
    app: &App,
    list_hit: &mut Option<ListRegion>,
    detail_scroll_hit: &mut Option<ScrollRegion>,
) {
    let Modal::Cve(modal) = &app.modal else {
        return;
    };

    *list_hit = None;
    *detail_scroll_hit = None;

    let r = centered_rect(area, 90, 85);
    f.render_widget(Clear, r);

    let title = if modal.syncing {
        " CVE index (syncing…) "
    } else {
        " CVE index "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(title, Theme::accent_bold()))
        .border_style(Theme::border_active())
        .style(Theme::panel());
    f.render_widget(block.clone(), r);
    let inner = block.inner(r);

    if modal.detail {
        let visible_lines = inner.height.max(1) as usize;
        *detail_scroll_hit = Some(ScrollRegion {
            area: inner,
            visible_lines,
        });
        render_detail(f, inner, modal);
        return;
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(inner);

    let prompt = Line::from(vec![
        Span::styled("/", Theme::accent_bold()),
        Span::styled(modal.query.clone(), Theme::accent_bold()),
        Span::styled("_", Theme::accent_bold()),
    ]);
    f.render_widget(Paragraph::new(prompt), layout[0]);

    let size = crate::config::format_storage_size(modal.db_size_bytes);
    let stats = if modal.db_total > 0 || modal.db_size_bytes > 0 {
        format!("{} CVEs · {} KEV · {}", modal.db_total, modal.db_kev, size,)
    } else {
        "empty index — press s to sync".into()
    };
    f.render_widget(Paragraph::new(stats).style(Theme::muted()), layout[1]);

    let total_pages = modal.total_pages();
    let page_start = if modal.results.is_empty() {
        0
    } else {
        modal.page * modal.page_size + 1
    };
    let page_end = modal.page * modal.page_size + modal.results.len();
    let mode = match (modal.kev_only, modal.poc_only) {
        (true, true) => "[KEV+POC]",
        (true, false) => "[KEV]",
        (false, true) => "[POC]",
        (false, false) => "[all]",
    };
    let chips = format!(
        "{}  {}-{} of {}  page {}/{}  j/k move  ←/→ page  Enter detail  y yank  s sync  K KEV{}  P PoC{}  Esc close",
        mode,
        page_start,
        page_end,
        modal.total_matches,
        modal.page + 1,
        total_pages,
        if modal.kev_only { "✓" } else { "" },
        if modal.poc_only { "✓" } else { "" },
    );
    f.render_widget(Paragraph::new(chips).style(Theme::muted()), layout[2]);

    let items: Vec<ListItem> = modal
        .results
        .iter()
        .map(|rec| {
            let kev = if rec.in_kev { " KEV" } else { "" };
            let poc = crate::cve::poc_index::lookup(&rec.id)
                .map(|e| format!(" {}", e.badge()))
                .unwrap_or_default();
            let sev = rec.severity.as_deref().unwrap_or("-");
            let cvss = rec.cvss_v31.map(|s| format!(" {s:.1}")).unwrap_or_default();
            let desc: String = rec.description.chars().take(60).collect();
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<18}", rec.id), Theme::accent_bold()),
                Span::styled(format!(" {sev}{cvss}"), Theme::warn()),
                Span::raw(format!(" {desc}{kev}")),
                Span::styled(poc, Theme::accent_bold()),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(modal.cursor.min(items.len() - 1)));
    }
    let list = List::new(items)
        .highlight_style(Theme::selected())
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, layout[3], &mut state);
    *list_hit = Some(ListRegion {
        panel: layout[3],
        list_inner: layout[3],
        list_offset: state.offset(),
    });

    let hint = if modal.db_total == 0 {
        "Empty index — press s to sync from NVD/KEV"
    } else if modal.results.is_empty() {
        "No matches — clear query or toggle KEV/PoC (need ~/pocs index.toml)"
    } else {
        ""
    };
    f.render_widget(Paragraph::new(hint).style(Theme::muted()), layout[4]);
}

fn render_detail(f: &mut Frame, area: Rect, modal: &CveModal) {
    let visible_lines = area.height.max(1) as usize;
    let scroll = modal
        .detail_scroll
        .min(max_detail_scroll(modal, visible_lines));

    let lines = build_detail_lines(modal);
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: true })
        .scroll((scroll as u16, 0));
    f.render_widget(para, area);
}
