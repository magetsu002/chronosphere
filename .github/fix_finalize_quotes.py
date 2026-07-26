#!/usr/bin/env python3
from pathlib import Path

path = Path("/tmp/finalize_hardening.py")
source = path.read_text()
old = r'''                "{trap}{scp_cmd} && {ssh_cmd}; ec=$?; echo \"$ec\" > {status}; {cleanup}",'''
new = r'''                r#"{trap}{scp_cmd} && {ssh_cmd}; ec=$?; echo "$ec" > {status}; {cleanup}"#,'''
count = source.count(old)
if count != 1:
    raise SystemExit(f"expected one interactive status format line, found {count}")
path.write_text(source.replace(old, new, 1))
