pub mod layout;
pub mod modals;
pub mod panels;
pub mod splash;
pub mod textarea_mouse;
pub mod theme;

use crate::app::{App, Focus, Modal};
use layout::HitRegions;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let mut hit = HitRegions {
        frame: area,
        ..Default::default()
    };

    // Splash screen takes over the whole frame until the user dismisses it.
    if let Some(splash) = app.splash.as_ref() {
        app.hit = hit;
        splash::draw(f, area, splash);
        return;
    }

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);

    let body = root[0];
    let status = root[1];

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(22),
            Constraint::Percentage(44),
            Constraint::Min(20),
        ])
        .split(body);

    panels::categories::render(f, columns[0], app, &mut hit.categories);
    panels::commands::render(f, columns[1], app, &mut hit.commands);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(columns[2]);

    hit.preview = layout::ScrollRegion::from_block(right[0]);
    panels::preview::render(f, right[0], app);
    panels::jobs::render(f, right[1], app, &mut hit.jobs);

    panels::status_bar::render(f, status, app, &mut hit.status_bar);

    hit.modal_popup = HitRegions::modal_popup_rect(area, &app.modal);
    app.hit = hit;

    let mut help_scroll = None;
    let mut job_log_scroll = None;
    let mut search_list = None;
    let mut cve_list = None;
    let mut cve_detail_scroll = None;
    let mut engagement_list = None;
    let mut target_list = None;
    let mut ap_list = None;
    let mut pivot_list = None;
    let mut creds_list = None;
    let mut variables_list = None;
    let mut edit_hit = None;

    match &app.modal {
        Modal::None => {}
        Modal::Help(_) => modals::help::render(f, area, app, &mut help_scroll),
        Modal::Engagement(_) => modals::engagement::render(f, area, app, &mut engagement_list),
        Modal::Target(_) => modals::target::render(f, area, app, &mut target_list),
        Modal::Ap(_) => modals::ap::render(f, area, app, &mut ap_list),
        Modal::Pivot(_) => modals::pivot::render(f, area, app, &mut pivot_list),
        Modal::Creds(_) => modals::creds::render(f, area, app, &mut creds_list),
        Modal::Variables(_) => modals::variables::render(f, area, app, &mut variables_list),
        Modal::Tools(_) => modals::tools::render(f, area, app),
        Modal::Search { .. } => modals::search::render(f, area, app, &mut search_list),
        Modal::Edit(_) => modals::edit::render(f, area, app, &mut edit_hit),
        Modal::JobLog(_) => modals::job_log::render(f, area, app, &mut job_log_scroll),
        Modal::Cve(_) => {
            modals::cve::render(f, area, app, &mut cve_list, &mut cve_detail_scroll);
        }
    }

    app.hit.help_scroll = help_scroll;
    app.hit.job_log_scroll = job_log_scroll;
    app.hit.search_list = search_list;
    app.hit.cve_list = cve_list;
    app.hit.cve_detail_scroll = cve_detail_scroll;
    app.hit.engagement_list = engagement_list;
    app.hit.target_list = target_list;
    app.hit.ap_list = ap_list;
    app.hit.pivot_list = pivot_list;
    app.hit.creds_list = creds_list;
    app.hit.variables_list = variables_list;
    app.hit.edit = edit_hit;

    let _ = Focus::Categories; // keep import alive
    let _ = Rect::default;
}

pub fn centered_rect(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    let h = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v[1]);
    h[1]
}
