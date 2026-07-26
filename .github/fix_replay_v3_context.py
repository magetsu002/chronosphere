#!/usr/bin/env python3
from pathlib import Path

path = Path("/tmp/replay_hardening_v3.py")
source = path.read_text()
old = '''    elif new_call not in source:
        raise RuntimeError("resolve context call not found")
'''
new = '''    elif new_call not in source:
        resolve_start = source.index("fn resolve(")
        resolve_end = source.index("\\nfn print_variables", resolve_start)
        resolve = source[resolve_start:resolve_end]
        call_start = resolve.index("let ctx = build_context(")
        call_end = resolve.index("\\n    let tmpl", call_start)
        canonical = """let ctx = build_context(
        &e,
        target_override,
        ap_override,
        cred_override,
        extra_vars,
    )?;"""
        resolve = resolve[:call_start] + canonical + resolve[call_end:]
        source = source[:resolve_start] + resolve + source[resolve_end:]
'''
if source.count(old) != 1:
    raise SystemExit(f"expected one context guard, found {source.count(old)}")
source = source.replace(old, new, 1)
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
