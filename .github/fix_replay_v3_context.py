#!/usr/bin/env python3
from pathlib import Path

path = Path("/tmp/replay_hardening_v3.py")
source = path.read_text()
start_marker = "    old_call = '''    let ctx = build_context("
start = source.index(start_marker)
end_marker = "    path.write_text(source)\n\n\ndef patch_secrets"
end = source.index(end_marker, start)
replacement = '''    resolve_start = source.index("fn resolve(")
    resolve_end = source.index("\\nfn print_variables", resolve_start)
    resolve = source[resolve_start:resolve_end]
    call_start = resolve.index("let ctx = build_context(")
    template_start = resolve.index("let tmpl =", call_start)
    call = ''' + '"""' + '''    let ctx = build_context(
        &e,
        target_override,
        ap_override,
        cred_override,
        extra_vars,
    )?;
    ''' + '"""' + '''
    resolve = resolve[:call_start] + call + resolve[template_start:]
    source = source[:resolve_start] + resolve + source[resolve_end:]
    path.write_text(source)


def patch_secrets'''
source = source[:start] + replacement + source[end + len(end_marker):]
source = source.replace(
    '        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    '        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)\n        Path(".github/fix_replay_v3_context.py").unlink(missing_ok=True)\n        Path(".github/v3-replay-failure.txt").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    1,
)
source = source.replace(
    '        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    '        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)\n        Path(".github/fix_replay_v3_context.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    1,
)
path.write_text(source)
