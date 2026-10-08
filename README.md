# patch-report

[![CI](https://github.com/int3erlud3/patch-report/actions/workflows/ci.yml/badge.svg)](https://github.com/int3erlud3/patch-report/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```text
              _      _                             _
   _ __  __ _| |_ __| |_ ___ _ _ ___ _ __  ___ _ _| |_
  | '_ \/ _` |  _/ _| ' \___| '_/ -_) '_ \/ _ \ '_|  _|
  | .__/\__,_|\__\__|_||_|  |_| \___| .__/\___/_|  \__|
  |_|                               |_|

+====================================================================+
|  PATCH REPORT  ::  Pending & Security Update Audit                 |
+--------------------------------------------------------------------+
|  dnf and apt update status with reboot-required detection          |
|  v1.0.0  -  Bastion Ops Toolkit  -  by int3erlud3                  |
+====================================================================+
```

Answer the patch-day questions for a Linux server in one command: *how many updates
are pending, which of them are security fixes, and does the host need a reboot?*
Works on **RHEL / Oracle Linux / Rocky / Alma / Fedora (dnf)** and
**Debian / Ubuntu (apt)**, prints a readable table or JSON, and returns
**monitoring-friendly exit codes**. Strictly **read-only**.

## Features

- Auto-detects the package manager from `/etc/os-release` (`--backend` to override)
- **dnf**: `check-update` + `updateinfo list --security` (dnf4 and dnf5 formats) with
  advisory IDs and severities (e.g. `ELSA-2024-2394 (Important)`); reboot detection via
  `needs-restarting -r`
- **apt**: `apt list --upgradable` from the existing cache, security updates detected by
  the `*-security` suite; reboot detection via `/run/reboot-required(.pkgs)`
- Text or JSON output, `--security-only` filter, `--cache-only` for dnf
- Runs commands without a shell, with a fixed `PATH` and `LC_ALL=C`, and a timeout

## Installation

```bash
git clone https://github.com/int3erlud3/patch-report.git
cd patch-report
python3 -m pip install .        # Python 3.10+, no runtime dependencies
```

## Usage

```bash
patch-report                    # table
patch-report --security-only    # only security fixes
patch-report --format json | jq '.counts'
patch-report --backend dnf --cache-only   # no metadata download
```

Example output:

```text
OS: Oracle Linux Server 9.4   Backend: dnf
Updates: 5 pending, 3 security   Reboot required: yes (kernel)

SECURITY  kernel                                   5.14.0-427.13.1.el9_4            ELSA-2024-2394 (Important)
SECURITY  kernel-core                              5.14.0-427.13.1.el9_4            ELSA-2024-2394 (Important)
SECURITY  openssl-libs                             1:3.0.7-27.0.1.el9               ELSA-2024-2447 (Moderate)
UPDATE    vim-enhanced                             2:8.2.2637-20.el9_1              ol9_appstream
STATUS: CRITICAL
```

### Exit codes

| Code | Status | Meaning |
|---|---|---|
| 0 | OK | No updates pending |
| 1 | WARNING | Non-security updates pending |
| 2 | CRITICAL | Security updates pending **or** reboot required |
| 3 | UNKNOWN | Package manager could not be queried / unsupported OS |

This makes it usable as a Nagios/Icinga/Zabbix check or in a cron job that only alerts
on `2`.

## Startup banner

Part of the **Bastion Ops Toolkit**. When run interactively, `patch-report` prints the
banner shown above to **stderr** – only if stderr is a terminal and never together with
`--format json`. Pipes, cron jobs and monitoring agents get unchanged output and exit
codes. Disable it with `--no-banner` or `NO_BANNER=1`.

## Development

```bash
make venv && make lint test security   # ruff, pytest (fixtures for dnf4/dnf5/apt), bandit, pip-audit
make scan                              # gitleaks secret scan (needs Docker)
```

## Security notes

- **Read-only**: no `apt update`, `upgrade`, `dnf upgrade` or any other state change.
  apt results reflect the current package cache – keep it fresh with your normal
  `apt update` timer (or unattended-upgrades).
- Root is not required; dnf may need it to read a root-owned cache with `--cache-only`.
- External commands run as fixed argument lists (no shell), with a minimal environment
  and a timeout; their output is parsed defensively.

## License

[MIT](LICENSE)
