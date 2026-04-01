from __future__ import annotations

from osint.ip import lookup_ip


class FakeResponse:
    def __init__(self, payload: dict[str, object], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> dict[str, object]:
        return self._payload


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    def get(self, url: str, params: dict[str, str], timeout: float) -> FakeResponse:
        assert url == "https://ipinfo.io/8.8.8.8/json"
        assert timeout == 4
        assert params == {}
        return self.response


def test_lookup_ip_returns_geolocation_and_asn() -> None:
    session = FakeSession(
        FakeResponse(
            {
                "ip": "8.8.8.8",
                "hostname": "dns.google",
                "city": "Mountain View",
                "region": "California",
                "country": "US",
                "postal": "94043",
                "timezone": "America/Los_Angeles",
                "loc": "37.4056,-122.0775",
                "org": "AS15169 Google LLC",
            }
        )
    )

    payload = lookup_ip("8.8.8.8", timeout=4, session=session)

    assert payload["ok"] is True
    assert payload["asn"] == "AS15169"
    assert payload["isp"] == "Google LLC"
    assert payload["country"] == "US"
    assert payload["classification"] == "global"


def test_lookup_ip_avoids_external_calls_for_private_addresses() -> None:
    class ExplodingSession:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("External lookup should not happen")

    payload = lookup_ip("192.168.1.5", session=ExplodingSession())

    assert payload["classification"] == "private"
    assert payload["summary"]["lookup_performed"] is False
    assert payload["is_global"] is False
