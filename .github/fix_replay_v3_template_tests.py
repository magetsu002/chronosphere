#!/usr/bin/env python3
from pathlib import Path

path = Path("/tmp/replay_hardening_v3.py")
source = path.read_text()
old = '''        apply_commit("219ffb073762f7d66bae10724ab672281046d5a7")
        apply_commit("33ea82916ff43882e60a6b16178cc3b5295376ae")
        patch_templates()
        commit_phase("fix: validate templates before command execution")
'''
new = '''        apply_commit("219ffb073762f7d66bae10724ab672281046d5a7")
        apply_commit("33ea82916ff43882e60a6b16178cc3b5295376ae")
        patch_templates()
        for module in (
            "src/render/condition.rs",
            "src/render/mod.rs",
            "src/library/mod.rs",
        ):
            write(module, run("git", "show", f"{V1}:{module}").stdout)
        commit_phase("fix: validate templates before command execution")
'''
if source.count(old) != 1:
    raise SystemExit(f"expected one template milestone block, found {source.count(old)}")
source = source.replace(old, new, 1)
source = source.replace(
    '        Path(".github/v3-replay-failure.txt").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    '        Path(".github/fix_replay_v3_template_tests.py").unlink(missing_ok=True)\n        Path(".github/v3-replay-failure.txt").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    1,
)
source = source.replace(
    '        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)\n        failure = Path(".github/v3-replay-failure.txt")',
    '        Path(".github/fix_replay_v3_template_tests.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)\n        failure = Path(".github/v3-replay-failure.txt")',
    1,
)
path.write_text(source)
