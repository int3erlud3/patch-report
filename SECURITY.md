# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository
instead. You can expect an initial response within 7 days.

## Security review notes

- Read-only by design: only query commands are executed (`apt list --upgradable`,
  `dnf check-update`, `dnf updateinfo list`, `needs-restarting -r`).
- No `shell=True`, no `eval`, fixed `PATH`/locale for child processes, timeouts.
- CI runs ruff (incl. flake8-bandit rules), Bandit, pip-audit and a gitleaks secret
  scan on every push and pull request; GitHub Actions are pinned to commit SHAs and
  run with `contents: read` only.
