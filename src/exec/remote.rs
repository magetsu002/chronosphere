//! Remote execution via scp script upload + ssh run on an active pivot.

use crate::engagement::Pivot;
use crate::exec::ssh::{SshConn, remote_script_path, write_remote_script};
use anyhow::Result;
use std::path::Path;

pub fn wrap_for_remote(
    user_command: &str,
    pivot: &Pivot,
    engagement_dir: &Path,
    target_name: Option<&str>,
    jobs_dir: &Path,
    job_id: &str,
    log_path: &str,
    status_path: &str,
    interactive: bool,
) -> Result<String> {
    let conn = SshConn::from_pivot(pivot, engagement_dir, target_name)?;
    let local_script = jobs_dir.join(format!("{}.remote.sh", job_id));
    write_remote_script(&local_script, user_command)?;
    let remote_script = remote_script_path(job_id);
    Ok(conn.remote_script_wrapper(
        &local_script,
        &remote_script,
        log_path,
        status_path,
        interactive,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engagement::Pivot;

    #[test]
    fn wrap_writes_local_script_and_returns_scp_ssh() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("chrono-remote-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        let jobs = dir.join("jobs");
        std::fs::create_dir_all(&jobs).unwrap();
        let ssh_dir = dir.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("id_web01"), "fake-key").unwrap();
        let pivot = Pivot {
            name: "web01".into(),
            ssh_host: Some("10.10.11.5".into()),
            ssh_user: Some("www-data".into()),
            ssh_port: None,
            ssh_identity: None,
            ssh_password: None,
            ligolo_interface: None,
            ligolo_server_addr: None,
            ligolo_routes: vec![],
            agent_path: None,
            notes: None,
        };
        let wrapped = wrap_for_remote(
            "id; whoami",
            &pivot,
            &dir,
            Some("web01"),
            &jobs,
            "abc-123",
            "/tmp/abc.log",
            "/tmp/abc.status",
            false,
        )
        .unwrap();
        let local = jobs.join("abc-123.remote.sh");
        assert!(local.exists());
        let body = std::fs::read_to_string(&local).unwrap();
        assert!(body.contains("id; whoami"));
        assert!(wrapped.contains("scp"));
        assert!(wrapped.contains("/tmp/chrono-abc-123.sh"));
        assert!(wrapped.contains("tee"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
