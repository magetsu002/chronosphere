use crate::app::{App, CveModal, Modal};
use crate::ui::centered_rect;
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let Modal::Cve(modal) = &app.modal else {
        return;
    };

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

    let chips = format!(
        "{}  {} shown  j/k move  Enter detail  y yank  s sync  K KEV{}  Esc close",
        if modal.kev_only { "[KEV]" } else { "[all]" },
        modal.results.len(),
        if modal.kev_only { "✓" } else { "" },
    );
    f.render_widget(Paragraph::new(chips).style(Theme::muted()), layout[2]);

    let items: Vec<ListItem> = modal
        .results
        .iter()
        .map(|rec| {
            let kev = if rec.in_kev { " KEV" } else { "" };
            let sev = rec.severity.as_deref().unwrap_or("-");
            let cvss = rec.cvss_v31.map(|s| format!(" {s:.1}")).unwrap_or_default();
            let desc: String = rec.description.chars().take(60).collect();
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<18}", rec.id), Theme::accent_bold()),
                Span::styled(format!(" {sev}{cvss}"), Theme::warn()),
                Span::raw(format!(" {desc}{kev}")),
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

    let hint = if modal.results.is_empty() {
        "No matches — run :cve then press s to sync, or type to search"
    } else {
        ""
    };
    f.render_widget(Paragraph::new(hint).style(Theme::muted()), layout[4]);
}

fn render_detail(f: &mut Frame, area: Rect, modal: &CveModal) {
    let rec = modal.results.get(modal.cursor);
    let Some(rec) = rec else {
        f.render_widget(Paragraph::new("No selection"), area);
        return;
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(&rec.id, Theme::accent_bold())));
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
    for line in rec.description.lines().take(12) {
        lines.push(Line::from(line.to_string()));
    }
    if !rec.references.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("References:", Theme::muted())));
        for r in rec.references.iter().take(5) {
            lines.push(Line::from(format!("  {}", r.url)));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Esc back  y yank id",
        Theme::muted(),
    )));

    let para = Paragraph::new(lines).wrap(Wrap { trim: true });
    f.render_widget(para, area);
}
