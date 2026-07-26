#!/usr/bin/env python3
import re
from pathlib import Path

path = Path("/tmp/replay_hardening_v3.py")
source = path.read_text()
pattern = re.compile(r"def patch_context\(\) -> None:\n.*?\n\ndef patch_secrets", re.S)
replacement = '''def patch_context() -> None:
    path = Path("src/cli.rs")
    source = path.read_text()
    source = source.replace(
        '    Engagement::load(root.join(&pick)).with_context(|| format!("load engagement {}", pick))',
        '    Engagement::load_named(root, &pick).with_context(|| format!("load engagement {}", pick))',
    )
    old = "    if let Some(name) = engagement {\\n        let dir = root.join(name);"
    new = "    if let Some(name) = engagement {\\n        Engagement::validate_name(name)?;\\n        let dir = root.join(name);"
    if old in source:
        source = source.replace(old, new, 1)

    start = source.index("fn build_context(")
    end = source.index("\\nfn resolve(", start)
    replacement = """fn build_context(
    engagement: &Engagement,
    target_override: &Option<String>,
    ap_override: &Option<String>,
    cred_override: &Option<String>,
    extra_vars: &[String],
) -> Result<RenderContext> {
    let mut ctx = RenderContext::default();
    let target = match target_override.as_deref() {
        Some(name) => Some(
            engagement
                .targets
                .targets
                .iter()
                .find(|target| target.name == name)
                .ok_or_else(|| anyhow!("no target named {}", name))?,
        ),
        None => engagement.targets.active(),
    };
    if let Some(target) = target {
        ctx.target = Some(target.clone());
    }

    let ap = match ap_override.as_deref() {
        Some(name) => Some(
            engagement
                .aps
                .aps
                .iter()
                .find(|ap| ap.name == name)
                .ok_or_else(|| anyhow!("no access point named {}", name))?,
        ),
        None => engagement.aps.active(),
    };
    if let Some(ap) = ap {
        ctx.ap = Some(ap.clone());
    }

    let profile = match cred_override.as_deref() {
        Some(name) => Some(
            engagement
                .profiles
                .profiles
                .iter()
                .find(|profile| profile.name == name)
                .ok_or_else(|| anyhow!("no credential profile named {}", name))?,
        ),
        None => engagement.profiles.active(),
    };
    if let Some(profile) = profile {
        ctx.profile = Some(profile.clone());
    }

    ctx.pivot_tunnel = engagement.pivots.active_tunnel().cloned();
    ctx.pivot_remote = engagement.pivots.active_remote().cloned();
    ctx.execution_mode = engagement.pivots.execution_mode;
    ctx.engagement_dir = Some(engagement.dir.clone());
    ctx.globals = engagement.variables.values.clone();
    for value in extra_vars {
        if let Some((key, value)) = value.split_once('=') {
            ctx.globals
                .insert(key.trim().to_string(), value.to_string());
        }
    }
    Ok(ctx)
}
"""
    source = source[:start] + replacement + source[end:]

    resolve_start = source.index("fn resolve(")
    resolve_end = source.index("\\nfn print_variables", resolve_start)
    resolve = source[resolve_start:resolve_end]
    match = re.search(r"let ctx = build_context\\((.*?)\\)\\s*\\??;", resolve, re.S)
    if match is None:
        raise RuntimeError("resolve context construction not found")
    canonical = """let ctx = build_context(
        &e,
        target_override,
        ap_override,
        cred_override,
        extra_vars,
    )?;"""
    resolve = resolve[:match.start()] + canonical + resolve[match.end():]
    source = source[:resolve_start] + resolve + source[resolve_end:]
    path.write_text(source)


def patch_secrets'''
updated, count = pattern.subn(replacement, source, count=1)
if count != 1:
    raise SystemExit(f"expected one patch_context function, replaced {count}")
updated = updated.replace(
    '        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    '        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)\n        Path(".github/fix_replay_v3_context.py").unlink(missing_ok=True)\n        Path(".github/v3-replay-failure.txt").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    1,
)
updated = updated.replace(
    '        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    '        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)\n        Path(".github/fix_replay_v3_context.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    1,
)
path.write_text(updated)
