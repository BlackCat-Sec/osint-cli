from __future__ import annotations

import json
from pathlib import Path

import pytest

from osint.email import lookup_email
from utils.helpers import OSINTError


class FakeHIBP:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.user_agent = None
        self.api_key = None

    def set_user_agent(self, value: str) -> None:
        self.user_agent = value

    def set_api_key(self, value: str) -> None:
        self.api_key = value

    def get_account_breaches(self, address: str, truncate_response: bool = False) -> object:
        assert address == "alice@example.com"
        assert truncate_response is False
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def load_fixture(filename: str) -> list[dict[str, object]]:
    return json.loads((Path(__file__).parent / "sample_data" / filename).read_text())


class FakeHTTPResponse:
    def __init__(
        self,
        payload: list[dict[str, object]],
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> list[dict[str, object]]:
        return self._payload


class FakeHTTPSession:
    def __init__(self, responses: list[FakeHTTPResponse]) -> None:
        self.responses = responses

    def get(
        self,
        url: str,
        headers: dict[str, str],
        params: dict[str, str],
        timeout: float,
    ) -> FakeHTTPResponse:
        assert "alice%40example.com" in url
        assert headers["hibp-api-key"] == "test-key"
        assert params == {"truncateResponse": "false"}
        assert timeout == 3
        return self.responses.pop(0)


def test_lookup_email_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HIBP_API_KEY", raising=False)

    with pytest.raises(OSINTError, match="HIBP_API_KEY"):
        lookup_email("alice@example.com", hibp_client=FakeHIBP([]))


def test_lookup_email_retries_once_after_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    sleeps: list[int] = []
    fake_hibp = FakeHIBP([RuntimeError("429 rate limit exceeded"), load_fixture("hibp_breaches.json")])

    payload = lookup_email(
        "alice@example.com",
        hibp_client=fake_hibp,
        sleeper=lambda seconds: sleeps.append(seconds),
    )

    assert sleeps == [2]
    assert payload["ok"] is True
    assert payload["breach_count"] == 1
    assert payload["breaches"][0]["name"] == "Adobe"
    assert fake_hibp.api_key == "test-key"


def test_lookup_email_falls_back_to_direct_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    monkeypatch.setattr(
        "osint.email._load_pyhibp",
        lambda: (_ for _ in ()).throw(OSINTError("pyhibp unavailable")),
    )
    session = FakeHTTPSession([FakeHTTPResponse(load_fixture("hibp_breaches.json"))])

    payload = lookup_email(
        "alice@example.com",
        timeout=3,
        session=session,
    )

    assert payload["lookup_mode"] == "direct-http"
    assert payload["breach_names"] == ["Adobe"]
    assert "warnings" in payload
