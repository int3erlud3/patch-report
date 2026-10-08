"""Collect pending package updates from dnf or apt. Strictly read-only.

Nothing here installs, removes or refreshes packages: apt is queried from its
existing package cache (``apt list --upgradable``) and dnf with ``check-update``
and ``updateinfo``, which only read repository metadata.
"""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
DNF_FAMILY = {"rhel", "ol", "centos", "fedora", "rocky", "almalinux", "amzn"}
APT_FAMILY = {"debian", "ubuntu", "linuxmint", "raspbian"}
DNF_ARCHES = {"x86_64", "noarch", "i686", "aarch64", "ppc64le", "s390x", "armv7hl", "src"}

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
STATUS_NAMES = ("OK", "WARNING", "CRITICAL", "UNKNOWN")

Runner = Callable[[Sequence[str]], tuple[int, str, str]]


class CollectError(RuntimeError):
    """Raised when the package manager cannot be queried."""


@dataclass
class Update:
    name: str
    version: str
    source: str = ""
    arch: str = ""
    current: str = ""
    security: bool = False
    advisory: str = ""
    severity: str = ""


@dataclass
class Report:
    backend: str
    os_name: str
    updates: list[Update] = field(default_factory=list)
    reboot_required: bool | None = None
    reboot_reason: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def security_count(self) -> int:
        return sum(1 for u in self.updates if u.security)

    @property
    def exit_code(self) -> int:
        if self.errors and not self.updates:
            return UNKNOWN
        if self.security_count or self.reboot_required:
            return CRITICAL
        if self.updates:
            return WARNING
        return UNKNOWN if self.errors else OK

    @property
    def status(self) -> str:
        return STATUS_NAMES[self.exit_code]

    def to_dict(self) -> dict:
        return {
            "backend": self.backend,
            "os": self.os_name,
            "status": self.status,
            "exit_code": self.exit_code,
            "reboot_required": self.reboot_required,
            "reboot_reason": self.reboot_reason,
            "counts": {"total": len(self.updates), "security": self.security_count},
            "updates": [asdict(u) for u in sorted(self.updates, key=_sort_key)],
            "errors": self.errors,
        }


def _sort_key(u: Update) -> tuple[bool, str]:
    return (not u.security, u.name)


def run_command(argv: Sequence[str], timeout: int = 600) -> tuple[int, str, str]:
    """Run a fixed command (no shell) with a minimal, predictable environment."""
    exe = shutil.which(argv[0], path=SAFE_PATH)
    if exe is None:
        raise FileNotFoundError(argv[0])
    proc = subprocess.run(  # noqa: S603  # nosec B603
        [exe, *argv[1:]], capture_output=True, text=True, env=SAFE_ENV, timeout=timeout, check=False
    )
    return proc.returncode, proc.stdout, proc.stderr


# ---- OS detection -----------------------------------------------------------
def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().isidentifier():
            data[key.strip()] = value.strip().strip("\"'")
    return data


def detect_backend(os_release: dict[str, str]) -> str:
    ids = {os_release.get("ID", "").lower(), *os_release.get("ID_LIKE", "").lower().split()}
    if ids & DNF_FAMILY:
        return "dnf"
    if ids & APT_FAMILY:
        return "apt"
    raise CollectError(f"unsupported distribution: {os_release.get('PRETTY_NAME', 'unknown')}")


# ---- apt ----------------------------------------------------------------------
_APT_LINE = re.compile(
    r"^(?P<name>[^/\s]+)/(?P<suites>\S+)\s+(?P<version>\S+)\s+(?P<arch>\S+)"
    r"(?:\s+\[upgradable from: (?P<current>[^\]]+)\])?"
)


def parse_apt_upgradable(text: str) -> list[Update]:
    updates = []
    for line in text.splitlines():
        m = _APT_LINE.match(line.strip())
        if not m:
            continue  # "Listing...", warnings, blank lines
        suites = m["suites"].split(",")
        updates.append(
            Update(
                name=m["name"],
                version=m["version"],
                source=m["suites"],
                arch=m["arch"],
                current=m["current"] or "",
                security=any(s.endswith("-security") or s.endswith("/updates") for s in suites),
            )
        )
    return updates


def apt_reboot_status(run_dir: Path = Path("/run")) -> tuple[bool, str]:
    flag = run_dir / "reboot-required"
    if not flag.exists():
        return False, ""
    pkgs_file = run_dir / "reboot-required.pkgs"
    pkgs = []
    if pkgs_file.is_file():
        pkgs = sorted({p.strip() for p in pkgs_file.read_text(errors="replace").splitlines() if p.strip()})
    return True, ", ".join(pkgs) if pkgs else "reboot-required flag present"


def collect_apt(runner: Runner, run_dir: Path = Path("/run")) -> tuple[list[Update], bool, str]:
    rc, out, err = runner(["apt", "list", "--upgradable"])
    if rc != 0:
        raise CollectError(f"apt list failed (exit {rc}): {err.strip()[:200]}")
    reboot, reason = apt_reboot_status(run_dir)
    return parse_apt_upgradable(out), reboot, reason


# ---- dnf ----------------------------------------------------------------------
def _split_name_arch(token: str) -> tuple[str, str] | None:
    name, sep, arch = token.rpartition(".")
    if sep and arch in DNF_ARCHES:
        return name, arch
    return None


def parse_dnf_check_update(text: str) -> list[Update]:
    """Parse ``dnf -q check-update`` (handles wrapped lines, ignores obsoletes)."""
    updates: list[Update] = []
    pending: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith(("obsoleting packages", "security:")):
            break
        tokens = pending + line.split()
        if len(tokens) < 3:
            pending = tokens  # long package names wrap onto the next line
            continue
        pending = []
        parsed = _split_name_arch(tokens[0])
        if parsed is None or len(tokens) != 3:
            continue  # "Last metadata expiration check", headers, noise
        name, arch = parsed
        updates.append(Update(name=name, version=tokens[1], source=tokens[2], arch=arch))
    return updates


def _nevra_name(nevra: str) -> str:
    base = nevra
    parsed = _split_name_arch(nevra)
    if parsed:
        base = parsed[0]
    parts = base.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else base


def parse_dnf_security(text: str) -> dict[str, tuple[str, str]]:
    """Map package name -> (advisory, severity) from dnf4 ``updateinfo list`` or dnf5 ``advisory list``."""
    result: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        tokens = line.split()
        if len(tokens) < 3 or tokens[0].lower() == "name":
            continue
        if tokens[1].endswith("/Sec."):  # dnf4: ID Severity/Sec. NEVRA
            advisory, severity, nevra = tokens[0], tokens[1].split("/")[0], tokens[2]
        elif tokens[1].lower() == "security" and len(tokens) >= 4:  # dnf5: ID security Severity NEVRA ...
            advisory, severity, nevra = tokens[0], tokens[2], tokens[3]
        else:
            continue
        result.setdefault(_nevra_name(nevra), (advisory, severity))
    return result


def dnf_reboot_status(runner: Runner) -> tuple[bool | None, str]:
    for argv in (["needs-restarting", "-r"], ["dnf", "-q", "needs-restarting", "-r"]):
        try:
            rc, out, _ = runner(argv)
        except FileNotFoundError:
            continue
        if rc == 0:
            return False, ""
        if rc == 1:
            lines = [ln.strip(" *") for ln in out.splitlines() if ln.strip().startswith("*")]
            return True, ", ".join(lines) or "core libraries or services updated"
    return None, "needs-restarting not available (install dnf-utils)"


def collect_dnf(runner: Runner, cache_only: bool = False) -> tuple[list[Update], bool | None, str]:
    base = ["dnf", "-q", *(["-C"] if cache_only else [])]
    rc, out, err = runner([*base, "check-update"])
    if rc not in (0, 100):  # 100 = updates available
        raise CollectError(f"dnf check-update failed (exit {rc}): {err.strip()[:200]}")
    updates = parse_dnf_check_update(out) if rc == 100 else []
    if updates:
        rc, out, _ = runner([*base, "updateinfo", "list", "--security", "--available"])
        security = parse_dnf_security(out) if rc == 0 else {}
        for u in updates:
            if u.name in security:
                u.security = True
                u.advisory, u.severity = security[u.name]
    reboot, reason = dnf_reboot_status(runner)
    return updates, reboot, reason


def collect(
    backend: str = "auto",
    runner: Runner = run_command,
    os_release: dict[str, str] | None = None,
    cache_only: bool = False,
    run_dir: Path = Path("/run"),
) -> Report:
    if os_release is None:
        try:
            os_release = read_os_release()
        except OSError:
            os_release = {}
    os_name = os_release.get("PRETTY_NAME", "unknown")
    report = Report(backend=backend, os_name=os_name)
    try:
        if backend == "auto":
            report.backend = backend = detect_backend(os_release)
        if backend == "dnf":
            report.updates, report.reboot_required, report.reboot_reason = collect_dnf(runner, cache_only)
        else:
            report.updates, report.reboot_required, report.reboot_reason = collect_apt(runner, run_dir)
    except (CollectError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        report.errors.append(f"{type(exc).__name__}: {exc}")
    return report
