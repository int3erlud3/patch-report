import subprocess

import pytest

from patch_report import collect as c


def test_detect_backend(fixtures):
    assert c.detect_backend(c.read_os_release(fixtures / "os-release-ol9")) == "dnf"
    assert c.detect_backend(c.read_os_release(fixtures / "os-release-ubuntu")) == "apt"
    with pytest.raises(c.CollectError):
        c.detect_backend({"ID": "alpine", "PRETTY_NAME": "Alpine"})


def test_parse_apt_marks_security_suites(fixtures):
    updates = {u.name: u for u in c.parse_apt_upgradable((fixtures / "apt_upgradable.txt").read_text())}
    assert set(updates) == {"libssl3", "openssl", "vim-tiny", "curl", "tzdata"}
    assert updates["openssl"].security and updates["curl"].security
    assert not updates["vim-tiny"].security and not updates["tzdata"].security
    assert updates["openssl"].current == "3.0.2-0ubuntu1.15"
    assert updates["vim-tiny"].version == "2:8.2.3995-1ubuntu2.17"


def test_parse_dnf_check_update_handles_wrapping_and_obsoletes(fixtures):
    updates = c.parse_dnf_check_update((fixtures / "dnf_check_update.txt").read_text())
    names = [u.name for u in updates]
    assert names == [
        "kernel",
        "kernel-core",
        "openssl-libs",
        "python3-a-very-long-package-name-that-wraps",
        "vim-enhanced",
    ]
    assert "grub2-tools" not in names  # obsoletes section ignored
    assert updates[3].version == "2.1.0-3.el9"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "dnf_updateinfo_dnf4.txt",
            {"kernel": "Important", "kernel-core": "Important", "openssl-libs": "Moderate"},
        ),
        ("dnf_advisory_dnf5.txt", {"kernel": "Important", "openssl-libs": "Moderate"}),
    ],
)
def test_parse_dnf_security_formats(fixtures, name, expected):
    parsed = c.parse_dnf_security((fixtures / name).read_text())
    assert {k: v[1] for k, v in parsed.items()} == expected


def test_collect_dnf_end_to_end(fake_runner):
    runner = fake_runner(
        {
            "dnf -q check-update": (100, "dnf_check_update.txt"),
            "dnf -q updateinfo": (0, "dnf_updateinfo_dnf4.txt"),
            "needs-restarting -r": (1, ""),
        }
    )
    report = c.collect(backend="dnf", runner=runner, os_release={"PRETTY_NAME": "OL9"})
    assert report.security_count == 3
    assert report.reboot_required is True
    assert report.exit_code == c.CRITICAL
    kernel = next(u for u in report.updates if u.name == "kernel")
    assert (kernel.advisory, kernel.severity) == ("ELSA-2024-2394", "Important")


def test_collect_dnf_cache_only_and_no_updates(fake_runner):
    runner = fake_runner({"dnf -q -C check-update": (0, ""), "needs-restarting -r": (0, "")})
    report = c.collect(backend="dnf", runner=runner, cache_only=True, os_release={})
    assert report.updates == [] and report.reboot_required is False
    assert report.status == "OK"
    assert all("updateinfo" not in call for call in runner.calls)


def test_dnf_reboot_unknown_without_tools(fake_runner):
    runner = fake_runner({"dnf -q check-update": (0, "")})
    report = c.collect(backend="dnf", runner=runner, os_release={})
    assert report.reboot_required is None
    assert "dnf-utils" in report.reboot_reason


def test_dnf_failure_is_unknown(fake_runner):
    runner = fake_runner({"dnf -q check-update": (1, "")})
    report = c.collect(backend="dnf", runner=runner, os_release={})
    assert report.exit_code == c.UNKNOWN
    assert report.errors


def test_collect_apt_with_reboot_flag(fake_runner, tmp_path):
    (tmp_path / "reboot-required").write_text("*** System restart required ***\n")
    (tmp_path / "reboot-required.pkgs").write_text("linux-image-6.8.0-45-generic\nlibc6\nlibc6\n")
    runner = fake_runner({"apt list --upgradable": (0, "apt_upgradable.txt")})
    report = c.collect(backend="apt", runner=runner, os_release={}, run_dir=tmp_path)
    assert report.reboot_required is True
    assert report.reboot_reason == "libc6, linux-image-6.8.0-45-generic"
    assert report.security_count == 3
    assert runner.calls == [["apt", "list", "--upgradable"]]  # read-only: no apt update/upgrade


def test_apt_only_non_security_is_warning(fake_runner, tmp_path, fixtures):
    text = "Listing...\ntzdata/stable-updates 2024b-0+deb12u1 all [upgradable from: 2024a-0+deb12u1]\n"
    (tmp_path / "f.txt").write_text(text)

    def runner(argv):
        return 0, text, ""

    report = c.collect(backend="apt", runner=runner, os_release={}, run_dir=tmp_path)
    assert report.exit_code == c.WARNING


def test_auto_detection_and_unsupported(fake_runner):
    report = c.collect(backend="auto", runner=fake_runner({}), os_release={"ID": "alpine"})
    assert report.exit_code == c.UNKNOWN
    assert "unsupported distribution" in report.errors[0]


def test_timeout_is_reported(tmp_path):
    def runner(argv):
        raise subprocess.TimeoutExpired(argv, 1)

    report = c.collect(backend="apt", runner=runner, os_release={}, run_dir=tmp_path)
    assert report.exit_code == c.UNKNOWN


def test_run_command_uses_fixed_env(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs, argv=argv)
        return subprocess.CompletedProcess(argv, 0, "out", "")

    monkeypatch.setattr(c.shutil, "which", lambda name, path=None: f"/usr/bin/{name}")
    monkeypatch.setattr(c.subprocess, "run", fake_run)
    assert c.run_command(["apt", "list"]) == (0, "out", "")
    assert seen["env"] == c.SAFE_ENV
    assert "shell" not in seen
    monkeypatch.setattr(c.shutil, "which", lambda name, path=None: None)
    with pytest.raises(FileNotFoundError):
        c.run_command(["dnf"])
