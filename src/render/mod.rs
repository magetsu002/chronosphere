pub mod condition;
pub mod context;
pub mod helpers;
pub mod placeholders;

pub use context::RenderContext;

use anyhow::Result;

#[derive(Debug, Clone, Default)]
pub struct RenderResult {
    pub resolved: String,
    pub unresolved: Vec<String>,
}

pub fn render(template: &str, ctx: &RenderContext) -> Result<RenderResult> {
    let after_placeholders = expand_placeholders(template, ctx);
    let resolved = helpers::expand_helpers(&after_placeholders.text)?;
    Ok(RenderResult {
        resolved,
        unresolved: after_placeholders.unresolved,
    })
}

struct PlaceholderPass {
    text: String,
    unresolved: Vec<String>,
}

/// Replaces `{name}` with the resolved value from `ctx`. Unknown names are left as `{name}` and
/// reported via the `unresolved` list so the UI can flag them.
///
/// Escape: `{{` and `}}` collapse to literal braces (so it's safe to keep things like awk programs in templates).
fn expand_placeholders(template: &str, ctx: &RenderContext) -> PlaceholderPass {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len());
    let mut unresolved = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '{' && i + 1 < bytes.len() && bytes[i + 1] as char == '{' {
            out.push('{');
            i += 2;
            continue;
        }
        if c == '}' && i + 1 < bytes.len() && bytes[i + 1] as char == '}' {
            out.push('}');
            i += 2;
            continue;
        }
        if c == '$' && i + 1 < bytes.len() && bytes[i + 1] as char == '{' {
            // leave ${...} sequences untouched here; helpers pass handles them.
            // copy to matching closing brace literally so `{` inside an inner ${} isn't grabbed.
            out.push('$');
            i += 1;
            continue;
        }
        if c == '{' {
            if let Some(end) = template[i + 1..].find('}') {
                let name = &template[i + 1..i + 1 + end];
                if name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                    && !name.is_empty()
                {
                    if let Some(val) = ctx.resolve(name) {
                        out.push_str(&val);
                    } else {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                        if !unresolved.iter().any(|x: &String| x == name) {
                            unresolved.push(name.to_string());
                        }
                    }
                    i += 1 + end + 1;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    PlaceholderPass {
        text: out,
        unresolved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engagement::{
        AccessPoint, CredKind, CredentialProfile, ExecutionMode, Pivot, Target,
    };
    use std::path::PathBuf;

    fn ctx() -> RenderContext {
        let mut c = RenderContext::default();
        c.target = Some(Target {
            name: "dc01".into(),
            ip: Some("10.10.11.10".into()),
            hostname: Some("DC01.CORP.LOCAL".into()),
            dc_name: Some("DC01".into()),
            lhost: Some("10.10.14.5".into()),
            lport: Some(4444),
            notes: None,
        });
        c.profile = Some(CredentialProfile {
            name: "jane".into(),
            username: "jane".into(),
            domain: Some("CORP".into()),
            kind: CredKind::Plaintext,
            password: Some("P@ss".into()),
            nt_hash: None,
            ticket_path: None,
            notes: None,
        });
        c
    }

    #[test]
    fn substitutes_known_placeholders() {
        let out = render("smbclient -L {target} -U '{user}'", &ctx()).unwrap();
        assert_eq!(out.resolved, "smbclient -L 10.10.11.10 -U 'jane'");
        assert!(out.unresolved.is_empty());
    }

    #[test]
    fn web_host_prefers_hostname() {
        let out = render("curl -kI http://{web_host}", &ctx()).unwrap();
        assert_eq!(out.resolved, "curl -kI http://DC01.CORP.LOCAL");
    }

    #[test]
    fn web_base_builds_url() {
        let out = render("feroxbuster -u {web_base}", &ctx()).unwrap();
        assert_eq!(out.resolved, "feroxbuster -u http://DC01.CORP.LOCAL");
    }

    #[test]
    fn vhost_root_strips_subdomain() {
        let mut c = ctx();
        c.target.as_mut().unwrap().hostname = Some("sub1.target.htb".into());
        let out = render("Host: FUZZ.{vhost_root}", &c).unwrap();
        assert_eq!(out.resolved, "Host: FUZZ.target.htb");
    }

    #[test]
    fn ap_fields_override_globals() {
        let mut c = RenderContext::default();
        c.ap = Some(AccessPoint {
            name: "htw".into(),
            ssid: Some("HackTheWireless".into()),
            bssid: Some("86:FC:9F:5D:67:4E".into()),
            channel: Some("6".into()),
            station: None,
            wpa_psk: Some("42b5215eb129abec043d7f32596f4f90".into()),
            wps_pin: None,
            capture: None,
            vendor: None,
            notes: None,
        });
        c.globals.insert("ssid".into(), "OtherNet".into());
        let out = render("reaver -b {bssid} -c {channel} -p {wpa_psk}", &c).unwrap();
        assert!(out.resolved.contains("86:FC:9F:5D:67:4E"));
        assert!(out.resolved.contains("42b5215e"));
        assert!(!out.resolved.contains("OtherNet"));
    }

    #[test]
    fn leaves_unknown_in_place_and_reports() {
        let out = render("nxc smb {target} {made_up}", &ctx()).unwrap();
        assert!(out.resolved.contains("{made_up}"));
        assert_eq!(out.unresolved, vec!["made_up".to_string()]);
    }

    #[test]
    fn pivot_placeholders_from_active_tunnel() {
        let mut c = RenderContext::default();
        c.pivot_tunnel = Some(Pivot {
            name: "web01".into(),
            ssh_host: Some("10.10.11.5".into()),
            ssh_user: Some("www-data".into()),
            ssh_port: None,
            ssh_identity: None,
            ssh_password: None,
            ligolo_interface: Some("ligolo".into()),
            ligolo_server_addr: Some("0.0.0.0:11601".into()),
            ligolo_routes: vec!["10.10.11.0/24".into()],
            agent_path: Some("/tmp/agent".into()),
            notes: None,
        });
        c.execution_mode = ExecutionMode::Local;
        let out = render(
            "route {ligolo_route} dev {tun_iface} user {pivot_user}@{pivot_host} agent {agent_path}",
            &c,
        )
        .unwrap();
        assert!(out.resolved.contains("10.10.11.0/24"));
        assert!(out.resolved.contains("ligolo"));
        assert!(out.resolved.contains("www-data"));
        assert!(out.resolved.contains("10.10.11.5"));
        assert!(out.resolved.contains("/tmp/agent"));
    }

    #[test]
    fn execution_mode_placeholder() {
        let mut c = RenderContext::default();
        c.execution_mode = ExecutionMode::Remote;
        let out = render("mode={execution_mode}", &c).unwrap();
        assert_eq!(out.resolved, "mode=remote");
    }

    #[test]
    fn pivot_ssh_key_defaults_to_engagement_ssh_id_target() {
        let mut c = RenderContext::default();
        c.target = Some(Target {
            name: "dc01".into(),
            ip: Some("10.10.11.10".into()),
            hostname: None,
            dc_name: None,
            lhost: None,
            lport: None,
            notes: None,
        });
        c.engagement_dir = Some(PathBuf::from("/tmp/engagement-test"));
        let out = render("key={pivot_ssh_key} pub={pivot_ssh_key_pub}", &c).unwrap();
        assert!(out.resolved.contains("/tmp/engagement-test/.ssh/id_dc01"));
        assert!(out.resolved.contains(".pub"));
    }

    #[test]
    fn pivot_ssh_key_uses_identity_override() {
        let mut c = RenderContext::default();
        c.pivot_remote = Some(Pivot {
            name: "web01".into(),
            ssh_host: Some("10.0.0.1".into()),
            ssh_user: Some("root".into()),
            ssh_port: None,
            ssh_identity: Some("/custom/key".into()),
            ssh_password: None,
            ligolo_interface: None,
            ligolo_server_addr: None,
            ligolo_routes: vec![],
            agent_path: None,
            notes: None,
        });
        c.engagement_dir = Some(PathBuf::from("/tmp/engagement-test"));
        let out = render("{pivot_ssh_key}", &c).unwrap();
        assert_eq!(out.resolved, "/custom/key");
    }

    #[test]
    fn double_braces_escape() {
        let out = render("awk '{{print $1}}' {target}", &ctx()).unwrap();
        assert!(out.resolved.starts_with("awk '{print $1}'"));
    }
}
