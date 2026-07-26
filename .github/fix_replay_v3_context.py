#!/usr/bin/env python3
from pathlib import Path

path = Path("/tmp/replay_hardening_v3.py")
source = path.read_text()
old = '''    elif new_call not in source:
        raise RuntimeError("resolve context call not found")
'''
new = '''    elif new_call not in source:
        updated, count = re.subn(
            r"(let ctx = build_context\\(.*?\\))\\s*;",
            lambda match: match.group(1) + "?;",
            source,
            count=1,
            flags=re.S,
        )
        if count != 1:
            raise RuntimeError("resolve context construction not found")
        source = updated
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
