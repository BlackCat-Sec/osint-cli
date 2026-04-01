from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import requests

from utils.helpers import (
    OSINTError,
    base_payload,
    build_requests_session,
    format_list_section,
    normalize_username,
    section_title,
    status_label,
)


@dataclass(frozen=True)
class UsernameService:
    slug: str
    name: str
    url_template: str
    found_statuses: frozenset[int]
    missing_statuses: frozenset[int]
    not_found_markers: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()


DEFAULT_SERVICES: tuple[UsernameService, ...] = (
    UsernameService(
        slug="github",
        name="GitHub",
        url_template="https://github.com/{username}",
        found_statuses=frozenset({200}),
        missing_statuses=frozenset({404}),
    ),
    UsernameService(
        slug="gitlab",
        name="GitLab",
        url_template="https://gitlab.com/{username}",
        found_statuses=frozenset({200}),
        missing_statuses=frozenset({404}),
    ),
    UsernameService(
        slug="reddit",
        name="Reddit",
        url_template="https://www.reddit.com/user/{username}/",
        found_statuses=frozenset({200}),
        missing_statuses=frozenset({404}),
        not_found_markers=("nobody on reddit goes by that name",),
    ),
    UsernameService(
        slug="keybase",
        name="Keybase",
        url_template="https://keybase.io/{username}",
        found_statuses=frozenset({200}),
        missing_statuses=frozenset({404}),
    ),
    UsernameService(
        slug="x",
        name="X",
        url_template="https://x.com/{username}",
        found_statuses=frozenset({200}),
        missing_statuses=frozenset({404}),
        aliases=("twitter",),
    ),
)

SERVICE_REGISTRY = {
    alias: service
    for service in DEFAULT_SERVICES
    for alias in (service.slug, *service.aliases)
}


def lookup_username(
    username: str,
    timeout: float = 10.0,
    session: requests.Session | None = None,
    services: str | tuple[UsernameService, ...] | None = DEFAULT_SERVICES,
) -> dict[str, Any]:
    handle = normalize_username(username)
    selected_services = _resolve_services(services)

    max_workers = min(8, len(selected_services))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(
            executor.map(
                lambda service: _check_service(
                    service=service,
                    username=handle,
                    timeout=timeout,
                    session=session,
                ),
                selected_services,
            )
        )

    warnings = [
        result["note"]
        for result in results
        if result["status"] == "error" and result.get("note")
    ]

    payload = base_payload(
        command="user",
        query=handle,
        sources=["requests"],
    )
    payload.update(
        {
            "services_requested": [service.slug for service in selected_services],
            "available_services": sorted(
                {service.slug for service in DEFAULT_SERVICES}
            ),
            "found_count": sum(
                1 for item in results if item["status"] == "found"
            ),
            "services": results,
            "summary": {
                "services_checked": len(results),
                "found": sum(
                    1 for item in results if item["status"] == "found"
                ),
                "not_found": sum(
                    1 for item in results if item["status"] == "not_found"
                ),
                "unknown": sum(
                    1 for item in results if item["status"] == "unknown"
                ),
                "errors": sum(
                    1 for item in results if item["status"] == "error"
                ),
            },
        }
    )
    if warnings:
        payload["warnings"] = warnings
    return payload


def render_user_result(payload: dict[str, Any]) -> str:
    lines = [section_title(f"Username: {payload['query']}")]
    lines.append(
        format_list_section(
            "Summary",
            [
                f"Positive matches: {payload.get('found_count', 0)}",
                "Services checked: "
                f"{payload.get('summary', {}).get('services_checked', 0)}",
            ],
        )
    )
    lines.append(section_title("Service Checks"))
    for service in payload.get("services", []):
        note = f" ({service['note']})" if service.get("note") else ""
        status_code = (
            f" [{service['status_code']}]" if service.get("status_code") else ""
        )
        lines.append(
            f"- {service['service']}: "
            f"{status_label(service['status'])}{status_code}{note}"
        )
        lines.append(f"  URL: {service['url']}")

    if payload.get("warnings"):
        lines.append(format_list_section("Warnings", payload["warnings"]))

    return "\n".join(lines)


def _resolve_services(
    services: str | tuple[UsernameService, ...] | None,
) -> tuple[UsernameService, ...]:
    if services is None:
        return DEFAULT_SERVICES

    if isinstance(services, tuple):
        return services

    requested = [
        item.strip().lower() for item in services.split(",") if item.strip()
    ]
    if not requested:
        raise OSINTError("At least one valid service must be provided.")

    resolved: list[UsernameService] = []
    seen: set[str] = set()
    unknown: list[str] = []

    for name in requested:
        service = SERVICE_REGISTRY.get(name)
        if service is None:
            unknown.append(name)
            continue
        if service.slug not in seen:
            resolved.append(service)
            seen.add(service.slug)

    if unknown:
        available = ", ".join(sorted({service.slug for service in DEFAULT_SERVICES}))
        raise OSINTError(
            "Unknown services requested: "
            + ", ".join(sorted(unknown))
            + ". Available services: "
            + available
        )

    return tuple(resolved)


def _check_service(
    service: UsernameService,
    username: str,
    timeout: float,
    session: requests.Session | None,
) -> dict[str, Any]:
    url = service.url_template.format(username=username)
    active_session = session or build_requests_session()
    try:
        response = active_session.get(url, allow_redirects=True, timeout=timeout)
        final_url = getattr(response, "url", url)
        return _normalize_service_result(
            service=service,
            url=final_url,
            status_code=response.status_code,
            body=response.text,
        )
    except requests.RequestException as exc:
        return {
            "service": service.name,
            "service_slug": service.slug,
            "url": url,
            "status": "error",
            "exists": None,
            "status_code": None,
            "note": str(exc),
        }
    finally:
        if session is None:
            active_session.close()


def _normalize_service_result(
    service: UsernameService,
    url: str,
    status_code: int,
    body: str,
) -> dict[str, Any]:
    lowered_body = body.lower()

    if status_code in service.found_statuses:
        for marker in service.not_found_markers:
            if marker in lowered_body:
                return _service_result(
                    service,
                    url,
                    "not_found",
                    False,
                    status_code,
                )
        return _service_result(service, url, "found", True, status_code)

    if status_code in service.missing_statuses:
        return _service_result(service, url, "not_found", False, status_code)

    return _service_result(
        service,
        url,
        "unknown",
        None,
        status_code,
        note="The response could not be confidently classified.",
    )


def _service_result(
    service: UsernameService,
    url: str,
    status: str,
    exists: bool | None,
    status_code: int | None,
    note: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "service": service.name,
        "service_slug": service.slug,
        "url": url,
        "status": status,
        "exists": exists,
        "status_code": status_code,
    }
    if note:
        payload["note"] = note
    return payload
