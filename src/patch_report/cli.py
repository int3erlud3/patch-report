"""Command line interface for patch-report."""

from __future__ import annotations

import argparse
import json
import socket
import sys
from collections.abc import Sequence
from datetime import datetime, timezone

from . import __version__
from .banner import maybe_print_banner, maybe_print_banner_for_info
from .collect import Report, collect


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="patch-report",
        description="Report pending and security updates (dnf/apt) and whether a reboot is required. "
        "Read-only: nothing is installed or refreshed.",
        epilog="Exit codes: 0 up to date, 1 updates pending, 2 security updates or reboot required, "
        "3 unknown/error.",
    )
    p.add_argument("-f", "--format", choices=("text", "json"), default="text")
    p.add_argument("-b", "--backend", choices=("auto", "dnf", "apt"), default="auto")
    p.add_argument("-s", "--security-only", action="store_true", help="list only security updates")
    p.add_argument("-C", "--cache-only", action="store_true", help="dnf: use cached metadata only (-C)")
    p.add_argument(
        "--no-banner", action="store_true", help="do not print the startup banner (or set NO_BANNER=1)"
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def render_text(report: Report, security_only: bool = False) -> str:
    reboot = {True: "yes", False: "no", None: "unknown"}[report.reboot_required]
    if report.reboot_reason:
        reboot += f" ({report.reboot_reason})"
    lines = [
        f"OS: {report.os_name}   Backend: {report.backend}",
        f"Updates: {len(report.updates)} pending, {report.security_count} security   "
        f"Reboot required: {reboot}",
        "",
    ]
    data = report.to_dict()["updates"]
    for u in data:
        if security_only and not u["security"]:
            continue
        kind = "SECURITY" if u["security"] else "UPDATE"
        extra = f"{u['advisory']} ({u['severity']})" if u["advisory"] else u["source"]
        lines.append(f"{kind:<9} {u['name']:<40} {u['version']:<32} {extra}")
    lines.extend(f"ERROR     {e}" for e in report.errors)
    lines.append(f"STATUS: {report.status}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    maybe_print_banner_for_info(argv)
    args = build_parser().parse_args(argv)
    if args.format != "json":  # never mix the banner with machine-readable output
        maybe_print_banner(args.no_banner)

    report = collect(backend=args.backend, cache_only=args.cache_only)
    if args.format == "json":
        data = report.to_dict()
        if args.security_only:
            data["updates"] = [u for u in data["updates"] if u["security"]]
        data = {
            "host": socket.gethostname(),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            **data,
        }
        print(json.dumps(data, indent=2))
    else:
        print(render_text(report, args.security_only))
    return report.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
