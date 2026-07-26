#!/usr/bin/env python3
from pathlib import Path

path = Path("/tmp/finalize_hardening.py")
source = path.read_text()
old = r'echo \"$ec\" > {status}'
new = r'echo \\\"$ec\\\" > {status}'
count = source.count(old)
if count != 1:
    raise SystemExit(f"expected one interactive status quote, found {count}")
path.write_text(source.replace(old, new, 1))
