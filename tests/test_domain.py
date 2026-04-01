from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from osint.domain import lookup_domain


class FakeRecord:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class FakeResolver:
    def __init__(self, dataset: dict[str, list[str]]) -> None:
        self.dataset = dataset

    def resolve(self, domain: str, record_type: str) -> list[FakeRecord]:
        assert domain == "github.com"
        return [FakeRecord(item) for item in self.dataset.get(record_type, [])]


def load_fixture(filename: str) -> dict[str, object]:
    raw = json.loads((Path(__file__).parent / "sample_data" / filename).read_text())
    for key in ("creation_date", "updated_date", "expiration_date"):
        raw[key] = [datetime.fromisoformat(value) for value in raw[key]]
    return raw


def test_lookup_domain_normalizes_whois_and_dns_records() -> None:
    fixture = load_fixture("domain_whois.json")
    resolver = FakeResolver(
        {
            "A": ["140.82.121.4"],
            "AAAA": [],
            "MX": ["1 aspmx.l.google.com."],
            "NS": ["dns1.p08.nsone.net.", "dns2.p08.nsone.net."],
            "TXT": ['"v=spf1 include:_spf.google.com ~all"'],
            "CNAME": [],
            "SOA": ["dns1.p08.nsone.net. hostmaster.github.com. 1 7200 900 1209600 86400"],
        }
    )

    payload = lookup_domain("github.com", resolver=resolver, whois_client=lambda _: fixture)

    assert payload["ok"] is True
    assert payload["command"] == "domain"
    assert payload["query"] == "github.com"
    assert payload["whois"]["registrar"] == "MarkMonitor Inc."
    assert payload["whois"]["creation_date"] == "2007-10-09"
    assert payload["dns"]["A"] == ["140.82.121.4"]
    assert payload["dns"]["NS"] == ["dns1.p08.nsone.net", "dns2.p08.nsone.net"]
    assert payload["dns"]["SOA"] == [
        "dns1.p08.nsone.net. hostmaster.github.com. 1 7200 900 1209600 86400"
    ]
    assert payload["summary"]["dns_record_types_with_answers"] == 5
