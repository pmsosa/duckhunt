# Security Policy

## Supported Versions

DuckHunter is maintained from the repository's default branch. Historical
binary builds are provided as convenience artifacts and should be treated as
legacy unless rebuilt from the current source.

| Version | Supported          |
| ------- | ------------------ |
| Current source | :white_check_mark: |
| Bundled 0.9 builds | :x: |

## Reporting a Vulnerability

Please avoid posting working exploit payloads publicly before there has been
time to investigate. Report issues through GitHub security advisories if
available for the repository, or open a GitHub issue with enough detail to
reproduce the defensive failure without including sensitive data.

Useful reports include:

- Windows version and Python version.
- Whether `pyHook` or `pyWinhook` is being used.
- Relevant `duckhunt.conf` settings.
- A minimal description of the HID-injection behavior, timing, and target
  window.
- The structured intrusion log line with secrets removed.
