from __future__ import annotations

from osint.user import lookup_username


class FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class FakeSession:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self.responses = responses

    def get(self, url: str, allow_redirects: bool, timeout: float) -> FakeResponse:
        assert allow_redirects is True
        assert timeout == 5
        return self.responses[url]


def test_lookup_username_classifies_services() -> None:
    session = FakeSession(
        {
            "https://github.com/johndoe": FakeResponse(200),
            "https://gitlab.com/johndoe": FakeResponse(404),
            "https://www.reddit.com/user/johndoe/": FakeResponse(200, "Nobody on Reddit goes by that name"),
            "https://keybase.io/johndoe": FakeResponse(200),
            "https://x.com/johndoe": FakeResponse(302),
        }
    )

    payload = lookup_username("johndoe", timeout=5, session=session)

    assert payload["ok"] is True
    assert payload["found_count"] == 2
    statuses = {item["service"]: item["status"] for item in payload["services"]}
    assert statuses["GitHub"] == "found"
    assert statuses["GitLab"] == "not_found"
    assert statuses["Reddit"] == "not_found"
    assert statuses["Keybase"] == "found"
    assert statuses["X"] == "unknown"


def test_lookup_username_respects_service_filter() -> None:
    session = FakeSession(
        {
            "https://github.com/johndoe": FakeResponse(200),
            "https://gitlab.com/johndoe": FakeResponse(404),
        }
    )

    payload = lookup_username(
        "johndoe",
        timeout=5,
        session=session,
        services="github,gitlab",
    )

    assert payload["services_requested"] == ["github", "gitlab"]
    assert len(payload["services"]) == 2
