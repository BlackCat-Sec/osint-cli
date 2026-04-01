from __future__ import annotations

import json

import pytest

from osint.cli import console_main


def test_cli_supports_json_flag_after_subcommand(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "osint.cli.lookup_domain",
        lambda name, timeout: {
            "command": "domain",
            "query": name,
            "whois": {"registrar": "Example Registrar"},
            "dns": {"A": ["93.184.216.34"]},
        },
    )

    exit_code = console_main(["domain", "example.com", "--json", "--timeout", "3"])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["query"] == "example.com"
    assert output["whois"]["registrar"] == "Example Registrar"


def test_cli_supports_json_flag_before_subcommand(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "osint.cli.lookup_ip",
        lambda address, timeout: {
            "command": "ip",
            "query": address,
            "country": "US",
        },
    )

    exit_code = console_main(["--json", "ip", "8.8.8.8"])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["query"] == "8.8.8.8"


def test_cli_rejects_non_positive_timeout() -> None:
    with pytest.raises(SystemExit) as exc_info:
        console_main(["ip", "8.8.8.8", "--timeout", "0"])

    assert exc_info.value.code == 2
