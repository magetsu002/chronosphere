#!/usr/bin/env python3
import re
from pathlib import Path

path = Path("/tmp/finalize_hardening.py")
source = path.read_text()
pattern = re.compile(
    r'^\s*"\{trap\}\{scp_cmd\} && \{ssh_cmd\}; ec=\$\?; echo .*? > \{status\}; \{cleanup\}",$',
    re.MULTILINE,
)
replacement = '                r#"{trap}{scp_cmd} && {ssh_cmd}; ec=$?; echo "$ec" > {status}; {cleanup}"#,'
updated, count = pattern.subn(replacement, source, count=1)
if count != 1:
    raise SystemExit(f"expected one interactive status format line, found {count}")
path.write_text(updated)
