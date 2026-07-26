//! Animated landing screen.
//!
//! Drawn on a `ratatui::widgets::canvas::Canvas` with `Marker::Braille` so we
//! get sub-character resolution. Three concurrent motions:
//!   1. clock hands (hour + minute) spinning fast — the "time-travel" event;
//!   2. an orbit dot circling the clock face;
//!   3. an inner pulse dot bouncing around the dial.
//!
//! Roman numerals are placed at the 12 hour positions. Bottom-right carries the
//! `CyberChronos · @CyberChronos00` signature.

use crate::ui::theme::Theme;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Circle, Line as CanvasLine};
use ratatui::widgets::{Block, Borders, Paragraph};

use std::f64::consts::PI;
use std::time::Instant;

pub struct SplashState {
    pub started_at: Instant,
}

impl SplashState {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
    pub fn elapsed_s(&self) -> f64 {
        self.started_at.elapsed().as_secs_f64()
    }
}

impl Default for SplashState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn draw(f: &mut Frame, area: Rect, splash: &SplashState) {
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Theme::border_active())
        .style(Theme::panel())
        .title(Span::styled(" chronosphere ", Theme::accent_bold()));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    // canvas | tagline (2 lines) | hint | signature
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(8),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    draw_clock(f, rows[0], splash);
    draw_tagline(f, rows[1]);
    draw_hint(f, rows[2]);
    draw_signature(f, rows[3]);
}

fn draw_clock(f: &mut Frame, area: Rect, splash: &SplashState) {
    let t = splash.elapsed_s();

    // angular velocities (rad/s) — minute hand sweeps the dial in ~1.5s.
    // Negative because canvas y grows upward; clock convention has hands sweep clockwise.
    let omega_min = -2.0 * PI / 1.5;
    let omega_hour = -2.0 * PI / 7.0;
    let omega_orbit = -2.0 * PI / 5.0;
    let omega_pulse = -2.0 * PI / 0.9;

    let start = -PI / 2.0; // 12 o'clock at top
    let a_min = start - omega_min * t;
    let a_hour = start - omega_hour * t;
    let a_orbit = start - omega_orbit * t;
    let a_pulse = start - omega_pulse * t;

    // Pick canvas bounds so the clock fits the available rect. The y-axis is
    // half-as-tall as terminal cells are roughly 2x as tall as wide; with Braille
    // we get ~2x vertical resolution per cell so an x:y bound ratio of 2:1 ≈ square.
    let cx = area.width as f64;
    let cy = area.height as f64;
    let aspect = (cx / cy).max(1.6); // never narrower than 1.6:1
    let half_y = 36.0;
    let half_x = half_y * aspect;

    // Radii in canvas units (y-units; canvas is uniform in its own coordinates).
    let r_dial = (half_y * 0.65).min(half_x * 0.55);
    let r_numerals = r_dial * 1.18;
    let r_orbit = r_dial * 1.55;
    let r_trail = 0.18 * r_dial;

    let romans = [
        "XII", "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI",
    ];

    let dial_color = Theme::BORDER;
    let tick_color = Theme::MUTED;
    let numeral_style = Style::default().fg(Theme::ACCENT);
    let numeral_style_cardinal = Style::default()
        .fg(Theme::ACCENT_BRIGHT)
        .add_modifier(ratatui::style::Modifier::BOLD);
    let hand_min_color = Theme::ACCENT;
    let hand_hour_color = Theme::ACCENT_BRIGHT;
    let pulse_color = Theme::MAGENTA;
    let orbit_color = Theme::ACCENT_BRIGHT;

    let canvas = Canvas::default()
        .marker(Marker::Braille)
        .x_bounds([-half_x, half_x])
        .y_bounds([-half_y, half_y])
        .background_color(Theme::PANEL_BG)
        .paint(move |ctx| {
            // ── dial face — concentric rings
            for ring in [r_dial, r_dial * 0.96] {
                ctx.draw(&Circle {
                    x: 0.0,
                    y: 0.0,
                    radius: ring,
                    color: dial_color,
                });
            }

            // 60 minute ticks; 12 bigger hour ticks
            for i in 0..60 {
                let a = i as f64 * (2.0 * PI / 60.0) + start;
                let is_hour = i % 5 == 0;
                let inner = if is_hour {
                    r_dial * 0.88
                } else {
                    r_dial * 0.92
                };
                let outer = r_dial * 0.96;
                ctx.draw(&CanvasLine {
                    x1: inner * a.cos(),
                    y1: inner * a.sin(),
                    x2: outer * a.cos(),
                    y2: outer * a.sin(),
                    color: if is_hour { Theme::BORDER } else { tick_color },
                });
            }

            // Roman numerals
            for (i, n) in romans.iter().enumerate() {
                let a = i as f64 * (2.0 * PI / 12.0) + start;
                let x = r_numerals * a.cos();
                let y = r_numerals * a.sin();
                let style = if matches!(i, 0 | 3 | 6 | 9) {
                    numeral_style_cardinal
                } else {
                    numeral_style
                };
                ctx.print(x, y, Span::styled(*n, style));
            }

            // Sphere trail — eight fading positions behind the orbit dot
            for k in 1..=10 {
                let a = a_orbit + (k as f64) * 0.10;
                let x = r_orbit * a.cos();
                let y = r_orbit * a.sin();
                let r = r_trail * (1.0 - k as f64 / 11.0);
                if r > 0.15 {
                    ctx.draw(&Circle {
                        x,
                        y,
                        radius: r,
                        color: Theme::BORDER,
                    });
                }
            }

            // Inner pulse dot — fast little orbit inside the dial
            ctx.draw(&Circle {
                x: r_dial * 0.45 * a_pulse.cos(),
                y: r_dial * 0.45 * a_pulse.sin(),
                radius: 0.6,
                color: pulse_color,
            });

            // Hour hand
            ctx.draw(&CanvasLine {
                x1: 0.0,
                y1: 0.0,
                x2: r_dial * 0.46 * a_hour.cos(),
                y2: r_dial * 0.46 * a_hour.sin(),
                color: hand_hour_color,
            });

            // Minute hand
            ctx.draw(&CanvasLine {
                x1: 0.0,
                y1: 0.0,
                x2: r_dial * 0.82 * a_min.cos(),
                y2: r_dial * 0.82 * a_min.sin(),
                color: hand_min_color,
            });

            // Center pin
            ctx.draw(&Circle {
                x: 0.0,
                y: 0.0,
                radius: 0.9,
                color: Theme::FG,
            });

            // Orbiting sphere (drawn last so it sits on top of the trail)
            ctx.draw(&Circle {
                x: r_orbit * a_orbit.cos(),
                y: r_orbit * a_orbit.sin(),
                radius: r_trail,
                color: orbit_color,
            });
        });

    f.render_widget(canvas, area);
}

fn draw_tagline(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(vec![
            Span::styled("クロノスフィアは巡る。 ", Theme::muted()),
            Span::styled("悪用（エクスプロイト）もまた同じ。", Theme::accent_bold()),
        ]),
        Line::from(vec![
            Span::styled("The Chronosphere revolves. ", Theme::muted()),
            Span::styled("So does the exploit.", Theme::accent_bold()),
        ]),
        Line::from(Span::styled(
            "vim TUI + MCP server for pentest engagement commands",
            Theme::muted(),
        )),
    ];
    let p = Paragraph::new(lines)
        .alignment(Alignment::Center)
        .style(Theme::panel());
    f.render_widget(p, area);
}

fn draw_hint(f: &mut Frame, area: Rect) {
    let hint = Line::from(vec![
        Span::styled("press ", Theme::muted()),
        Span::styled("any key", Theme::accent_bold()),
        Span::styled(" or ", Theme::muted()),
        Span::styled("click", Theme::accent_bold()),
        Span::styled(" to enter   ·   ", Theme::muted()),
        Span::styled("?", Theme::accent_bold()),
        Span::styled(" for help   ·   ", Theme::muted()),
        Span::styled(":q", Theme::accent_bold()),
        Span::styled(" to quit", Theme::muted()),
    ]);
    let p = Paragraph::new(hint)
        .alignment(Alignment::Center)
        .style(Theme::panel());
    f.render_widget(p, area);
}

fn draw_signature(f: &mut Frame, area: Rect) {
    let sig = Line::from(vec![
        Span::styled("by ", Theme::muted()),
        Span::styled("CyberChronos", Theme::magenta()),
        Span::styled(" · ", Theme::muted()),
        Span::styled("@CyberChronos00", Theme::accent_bold()),
    ]);
    let p = Paragraph::new(sig)
        .alignment(Alignment::Right)
        .style(Theme::panel());
    f.render_widget(p, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn renders_without_panic() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let splash = SplashState::new();
        terminal
            .draw(|f| draw(f, f.area(), &splash))
            .expect("draw splash");
        // Smoke: the signature text should land somewhere on the buffer.
        let buf = terminal.backend().buffer().clone();
        let s = buf.content().iter().map(|c| c.symbol()).collect::<String>();
        assert!(
            s.contains("CyberChronos") && s.contains("@CyberChronos00"),
            "signature missing from splash buffer"
        );
    }

    #[test]
    fn handles_small_area() {
        let backend = TestBackend::new(24, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        let splash = SplashState::new();
        terminal
            .draw(|f| draw(f, f.area(), &splash))
            .expect("draw on small area");
    }
}
