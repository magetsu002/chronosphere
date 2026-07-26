#!/usr/bin/env python3
from pathlib import Path

path = Path('/tmp/job_recovery_impl.py')
source = path.read_text()


def replace_once(old: str, new: str) -> None:
    global source
    count = source.count(old)
    if count != 1:
        raise SystemExit(f'expected one runner fragment, found {count}: {old[:100]!r}')
    source = source.replace(old, new, 1)


replace_once(
    '''    run("git", "commit", "-m", message)\n''',
    '''    run("git", "commit", "-m", message)\n    run("git", "push", "origin", f"HEAD:{WORK_BRANCH}")\n''',
)

replace_once(
    '''    replace_regex(\n        "src/mcp/tools.rs",\n        r"(async fn tool_list_jobs\\(args: Value, state: Arc<Mutex<State>>\\) -> Result<Value> \\{\\n)    let s = state\\.lock\\(\\)\\.await;",\n        r"\\1    let mut s = state.lock().await;\\n    refresh_recovered_jobs(&mut s);",\n    )\n''',
    '''    replace_regex(\n        "src/mcp/tools.rs",\n        r"(async fn tool_list_jobs\\(args: Value, state: Arc<Mutex<State>>\\) -> Result<Value> \\{.*?\\n)    let s = state\\.lock\\(\\)\\.await;",\n        r"\\1    let mut s = state.lock().await;\\n    refresh_recovered_jobs(&mut s);",\n        flags=re.S,\n    )\n''',
)

old_main = '''def main() -> None:\n    run("git", "config", "user.name", "Chronosphere Reliability")\n    run("git", "config", "user.email", "actions@users.noreply.github.com")\n    run("git", "fetch", "origin", "main", WORK_BRANCH)\n    run("git", "switch", WORK_BRANCH)\n    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()\n    if head != EXPECTED_BASE:\n        raise RuntimeError(f"unexpected work branch head: {head} != {EXPECTED_BASE}")\n\n    milestone_1()\n    milestone_2()\n    milestone_3()\n    milestone_4()\n    milestone_5()\n    milestone_6()\n\n    run("cargo", "fmt", "--check")\n'''
new_main = '''def main() -> None:\n    run("git", "config", "user.name", "Chronosphere Reliability")\n    run("git", "config", "user.email", "actions@users.noreply.github.com")\n    run("git", "fetch", "origin", "main", WORK_BRANCH)\n    run("git", "switch", WORK_BRANCH)\n\n    merge_base = subprocess.check_output(\n        ["git", "merge-base", "origin/main", "HEAD"], cwd=REPO, text=True\n    ).strip()\n    if merge_base != EXPECTED_BASE:\n        raise RuntimeError(\n            f"unexpected work branch merge base: {merge_base} != {EXPECTED_BASE}"\n        )\n\n    milestones = [\n        ("feat: persist subprocess runtime identity", milestone_1),\n        ("fix: reconcile stale jobs during startup", milestone_2),\n        ("fix: support safe cancellation after restart", milestone_3),\n        ("perf: stream bounded job tail and grep output", milestone_4),\n        ("test: cover subprocess recovery and large log streaming", milestone_5),\n        ("feat: expand doctor with stale job and orphan cleanup", milestone_6),\n    ]\n    completed = set(\n        subprocess.check_output(\n            ["git", "log", "--format=%s", "origin/main..HEAD"],\n            cwd=REPO,\n            text=True,\n        ).splitlines()\n    )\n    allowed = {message for message, _ in milestones}\n    unexpected = completed - allowed\n    if unexpected:\n        raise RuntimeError(f"unexpected commits on work branch: {sorted(unexpected)}")\n\n    for message, implementation in milestones:\n        if message in completed:\n            print(f"= already completed: {message}", flush=True)\n            continue\n        implementation()\n        completed.add(message)\n\n    run("cargo", "fmt", "--check")\n'''
replace_once(old_main, new_main)

path.write_text(source)
