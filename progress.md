Original prompt: keeping all current features innvaote advance improve and look at most recetn research to help and also add new features

Notes:
- Project is a Windows Python BadUSB/HID keystroke-injection defense tool, not a browser game.
- Recent research reviewed during this pass emphasizes that timing-only detection is easy to evade; stronger practical defenses combine keystroke dynamics, content/pattern context, behavior signals, and allowlist/sensitive-surface controls.
- Added rolling command-fragment detection and risk scoring to both `duckhunt.py` and `duckhunt-configurable.py` while preserving existing policies, blacklist/whitelist, adaptive threshold, low-variance, pattern signature, status export, warmup, and pause/resume behavior.
- Fixed Python 3 config loading for `duckhunt.conf` by using an explicit source loader.
- Verified syntax with `python -m py_compile duckhunt.py duckhunt-configurable.py setup.py`.
- Ran synthetic detector checks with stubbed Windows hook modules for normal typing, trusted injected auto-type, and a sensitive-window encoded PowerShell fragment.
- Further pass added timing-entropy detection, short-window risk-session accumulation, structured JSON Lines incident export, and Normal-mode lockout backoff.
- Expanded synthetic checks now cover manual terminal typing, trusted injected auto-type without session-risk carryover, encoded PowerShell fragments, and slow repetitive timing caught by entropy/session risk.

TODOs:
- Consider extracting duplicated detection logic into a shared module so GUI and daemon entry points cannot drift.
- Build a synthetic event unit-test harness with stubbed Windows hook modules for repeatable detector tests.
- Consider Windows USB device-arrival telemetry in a future pass to raise risk immediately after a new keyboard-like HID appears.
