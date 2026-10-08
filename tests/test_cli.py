import json

from patch_report import cli
from patch_report.collect import Report, Update


def fake_report():
    return Report(
        backend="apt",
        os_name="Ubuntu 24.04",
        updates=[
            Update("openssl", "3.0.13-0ubuntu3.4", "noble-security", security=True),
            Update("vim", "2:9.1.0016-1ubuntu7.3", "noble-updates"),
        ],
        reboot_required=False,
    )


def test_json_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "collect", lambda **kw: fake_report())
    rc = cli.main(["--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert data["status"] == "CRITICAL"
    assert data["counts"] == {"total": 2, "security": 1}
    assert data["updates"][0]["name"] == "openssl"  # security first
    assert {"host", "timestamp"} <= data.keys()


def test_security_only_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "collect", lambda **kw: fake_report())
    cli.main(["-f", "json", "--security-only"])
    assert [u["name"] for u in json.loads(capsys.readouterr().out)["updates"]] == ["openssl"]


def test_text_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "collect", lambda **kw: fake_report())
    assert cli.main(["--security-only"]) == 2
    out = capsys.readouterr().out
    assert "SECURITY  openssl" in out
    assert "vim" not in out.split("Reboot required")[1]
    assert out.rstrip().endswith("STATUS: CRITICAL")


def test_options_are_passed(monkeypatch, capsys):
    seen = {}

    def fake(**kw):
        seen.update(kw)
        return Report(backend="dnf", os_name="OL9", reboot_required=None, reboot_reason="n/a")

    monkeypatch.setattr(cli, "collect", fake)
    assert cli.main(["-b", "dnf", "-C"]) == 0
    assert seen == {"backend": "dnf", "cache_only": True}
    assert "Reboot required: unknown (n/a)" in capsys.readouterr().out
