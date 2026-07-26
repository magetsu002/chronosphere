use crate::app::App;
use crate::ui::layout::{StatusBarAction, StatusBarHits, StatusChipHit};
use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

pub fn render(f: &mut Frame, area: Rect, app: &App, hits: &mut StatusBarHits) {
    hits.bar = area;
    hits.chips.clear();
    let mut x = area.x;

    let advance =
        |hits: &mut StatusBarHits, x: &mut u16, text: &str, action: Option<StatusBarAction>| {
            let w = text.len() as u16;
            if w > 0 {
                if let Some(action) = action {
                    hits.chips.push(StatusChipHit {
                        area: Rect::new(*x, area.y, w, area.height.max(1)),
                        action,
                    });
                }
            }
            *x = x.saturating_add(w);
        };

    let mode = app.mode.label();
    let mode_style = match app.mode {
        crate::vim::Mode::Normal => Theme::accent_bold(),
        crate::vim::Mode::Insert => Theme::success().add_modifier(Modifier::BOLD),
        crate::vim::Mode::Command => Theme::magenta().add_modifier(Modifier::BOLD),
        crate::vim::Mode::Search | crate::vim::Mode::SearchGlobal => {
            Theme::warn().add_modifier(Modifier::BOLD)
        }
    };

    let engagement = app
        .engagement
        .as_ref()
        .map(|e| e.meta.name.clone())
        .unwrap_or_else(|| "no engagement".to_string());

    let target = app
        .engagement
        .as_ref()
        .and_then(|e| e.active_target())
        .map(|t| {
            let ident = t
                .hostname
                .clone()
                .or_else(|| t.ip.clone())
                .unwrap_or_else(|| t.name.clone());
            format!("{} ({})", ident, t.name)
        })
        .unwrap_or_else(|| "no target".to_string());

    let profile = app
        .engagement
        .as_ref()
        .and_then(|e| e.active_profile())
        .map(|p| match (&p.domain, p.kind) {
            (Some(d), _) => format!("{}\\{} [{}]", d, p.username, p.kind.as_str()),
            (None, _) => format!("{} [{}]", p.username, p.kind.as_str()),
        })
        .unwrap_or_else(|| "no creds".to_string());

    let ap = app
        .engagement
        .as_ref()
        .and_then(|e| e.active_ap())
        .map(|a| {
            let ident = a
                .ssid
                .clone()
                .or_else(|| a.bssid.clone())
                .unwrap_or_else(|| a.name.clone());
            format!("{} ({})", ident, a.name)
        })
        .unwrap_or_else(|| "no ap".to_string());

    let pivot = app
        .engagement
        .as_ref()
        .map(|e| {
            let mode = e.pivots.execution_mode.as_str();
            let tun = e
                .pivots
                .active_tunnel()
                .map(|p| p.name.as_str())
                .unwrap_or("-");
            let rem = e
                .pivots
                .active_remote()
                .map(|p| p.name.as_str())
                .unwrap_or("-");
            format!("exec:{} tun:{} rem:{}", mode, tun, rem)
        })
        .unwrap_or_else(|| "exec:local".to_string());

    let jobs = format!(
        "● {}  ✓ {}  ✗ {}",
        app.jobs_running_count(),
        app.jobs_completed_count(),
        app.jobs_failed_count()
    );

    let prefix = match app.mode {
        crate::vim::Mode::Command => format!(":{}", app.command_line_buf),
        crate::vim::Mode::Search => format!("/{}", app.search_buf),
        crate::vim::Mode::SearchGlobal => format!("g/{}", app.search_buf),
        _ => String::new(),
    };

    // Track clickable chip regions (mode label is not clickable).
    advance(hits, &mut x, &format!(" {} ", mode), None);
    advance(hits, &mut x, "│ ", None);
    advance(hits, &mut x, &engagement, Some(StatusBarAction::Engagement));
    advance(hits, &mut x, " │ ", None);
    advance(hits, &mut x, &target, Some(StatusBarAction::Target));
    advance(hits, &mut x, " │ ", None);
    advance(hits, &mut x, &ap, Some(StatusBarAction::Ap));
    advance(hits, &mut x, " │ ", None);
    advance(hits, &mut x, &pivot, Some(StatusBarAction::Pivot));
    advance(hits, &mut x, " │ ", None);
    advance(hits, &mut x, &profile, Some(StatusBarAction::Creds));
    advance(hits, &mut x, " │ ", None);
    advance(hits, &mut x, &jobs, Some(StatusBarAction::Jobs));

    let mut spans = vec![
        Span::styled(format!(" {} ", mode), mode_style),
        Span::raw("│ "),
        Span::styled(engagement, Theme::magenta()),
        Span::raw(" │ "),
        Span::styled(target, Theme::accent()),
        Span::raw(" │ "),
        Span::styled(ap, Theme::accent()),
        Span::raw(" │ "),
        Span::styled(pivot, Theme::warn()),
        Span::raw(" │ "),
        Span::styled(profile, Theme::accent_bold()),
        Span::raw(" │ "),
        Span::styled(jobs, Theme::muted()),
    ];

    if !prefix.is_empty() {
        advance(hits, &mut x, " │ ", None);
        advance(hits, &mut x, &prefix, None);
        spans.push(Span::raw(" │ "));
        spans.push(Span::styled(
            prefix,
            Theme::warn().add_modifier(Modifier::BOLD),
        ));
    }

    if let Some(msg) = &app.flash {
        let flash_text = format!(" │ {}", msg.text);
        advance(hits, &mut x, &flash_text, None);
        spans.push(Span::raw(" │ "));
        let style = if msg.is_error {
            Theme::error()
        } else {
            Theme::success()
        };
        spans.push(Span::styled(msg.text.clone(), style));
    }

    let p = Paragraph::new(Line::from(spans)).style(Theme::base());
    f.render_widget(p, area);
}
