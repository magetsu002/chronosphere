#!/usr/bin/env python3
from pathlib import Path

path = Path("/tmp/replay_hardening_v3.py")
source = path.read_text()
old = '        run("cargo", "test", "--locked", "--all-targets")\n'
new = '        run("bash", "-lc", "RUST_BACKTRACE=1 cargo test --locked --all-targets -- --test-threads=1 --nocapture")\n'
if source.count(old) != 1:
    raise SystemExit(f"expected one final test command, found {source.count(old)}")
source = source.replace(old, new, 1)
source = source.replace(
    '        Path(".github/v3-replay-failure.txt").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    '        Path(".github/fix_replay_v3_tests.py").unlink(missing_ok=True)\n        Path(".github/v3-replay-failure.txt").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    1,
)
source = source.replace(
    '        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)\n        failure = Path(".github/v3-replay-failure.txt")',
    '        Path(".github/fix_replay_v3_tests.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)\n        failure = Path(".github/v3-replay-failure.txt")',
    1,
)
path.write_text(source)
