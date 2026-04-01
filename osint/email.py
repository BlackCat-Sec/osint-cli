from __future__ import annotations

import os
import time
from typing import Any
from urllib.parse import quote

import requests

from utils.helpers import (
    OSINTError,
    base_payload,
    build_requests_session,
    format_key_value_section,
    format_list_section,
    mask_email,
    normalize_email,
    parse_retry_after,
    section_title,
)

DEFAULT_HIBP_USER_AGENT = "osint-cli/0.1.0 (defensive OSINT CLI)"
HIBP_BREACHED_ACCOUNT_URL = (
    "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
)


def lookup_email(
    address: str,
    timeout: float = 10.0,
    hibp_client: Any | None = None,
    session: requests.Session | None = None,
    sleeper=time.sleep,
) -> dict[str, Any]:
    email_address = normalize_email(address)
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        raise OSINTError("HIBP_API_KEY is required for email breach checks.")

    user_agent = os.getenv("OSINT_CLI_USER_AGENT", DEFAULT_HIBP_USER_AGENT)
    session = session or build_requests_session()
    warnings: list[str] = []
    lookup_mode = "pyhibp"

    if hibp_client is not None:
        breaches = _fetch_breaches_with_pyhibp(
            hibp_client=hibp_client,
            address=email_address,
            api_key=api_key,
            user_agent=user_agent,
            sleeper=sleeper,
        )
    else:
        try:
            hibp_client = _load_pyhibp()
            breaches = _fetch_breaches_with_pyhibp(
                hibp_client=hibp_client,
                address=email_address,
                api_key=api_key,
                user_agent=user_agent,
                sleeper=sleeper,
            )
        except OSINTError as exc:
            warnings.append(
                f"pyhibp lookup failed; using direct HIBP HTTP fallback: {exc}"
            )
            lookup_mode = "direct-http"
            breaches = _fetch_breaches_with_http(
                address=email_address,
                api_key=api_key,
                user_agent=user_agent,
                timeout=timeout,
                session=session,
                sleeper=sleeper,
            )

    normalized_breaches = [_normalize_breach(entry) for entry in breaches]
    exposed_classes = sorted(
        {
            data_class
            for breach in normalized_breaches
            for data_class in breach.get("data_classes", [])
        }
    )
    payload = base_payload(
        command="email",
        query=email_address,
        sources=["HaveIBeenPwned", lookup_mode],
    )
    payload.update(
        {
            "masked_query": mask_email(email_address),
            "lookup_mode": lookup_mode,
            "breach_count": len(normalized_breaches),
            "breach_names": [breach["name"] for breach in normalized_breaches],
            "exposed_data_classes": exposed_classes,
            "breaches": normalized_breaches,
            "summary": {
                "breaches_found": len(normalized_breaches),
                "verified_breaches": sum(
                    1 for breach in normalized_breaches if breach.get("verified")
                ),
                "sensitive_breaches": sum(
                    1 for breach in normalized_breaches if breach.get("sensitive")
                ),
            },
        }
    )
    if warnings:
        payload["warnings"] = warnings

    return payload


def _fetch_breaches_with_pyhibp(
    hibp_client: Any,
    address: str,
    api_key: str,
    user_agent: str,
    sleeper=time.sleep,
) -> list[dict[str, Any]]:
    _configure_hibp(hibp_client, api_key=api_key, user_agent=user_agent)

    try:
        return _fetch_account_breaches(hibp_client, address)
    except RuntimeError as exc:
        message = str(exc)
        lowered = message.lower()
        if "429" in message or "rate limit" in lowered:
            sleeper(2)
            return _fetch_account_breaches(hibp_client, address)
        if (
            "404" in message
            or "not found" in lowered
            or "not been pwned" in lowered
        ):
            return []
        raise OSINTError(f"HIBP request failed: {message}") from exc
    except Exception as exc:
        raise OSINTError(f"Email breach lookup failed: {exc}") from exc


def _fetch_breaches_with_http(
    address: str,
    api_key: str,
    user_agent: str,
    timeout: float,
    session: requests.Session,
    sleeper=time.sleep,
) -> list[dict[str, Any]]:
    headers = {
        "hibp-api-key": api_key,
        "user-agent": user_agent,
        "Accept": "application/json",
    }
    params = {
        "truncateResponse": "false",
    }
    url = HIBP_BREACHED_ACCOUNT_URL.format(account=quote(address, safe=""))

    for attempt in range(2):
        try:
            response = session.get(
                url,
                headers=headers,
                params=params,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            raise OSINTError(f"HIBP HTTP fallback failed: {exc}") from exc

        if response.status_code == 404:
            return []
        if response.status_code == 429:
            if attempt == 0:
                sleeper(parse_retry_after(response.headers.get("Retry-After")))
                continue
            raise OSINTError("HIBP rate limit reached after retry.")
        if response.status_code in {401, 403}:
            raise OSINTError(
                "HIBP rejected the request. Check HIBP_API_KEY and account access."
            )

        try:
            response.raise_for_status()
        except requests.RequestException as exc:
            raise OSINTError(f"HIBP HTTP fallback failed: {exc}") from exc

        return response.json()

    return []


def render_email_result(payload: dict[str, Any]) -> str:
    lines = [section_title(f"Email: {payload['masked_query']}")]
    lines.append(
        format_key_value_section(
            "Summary",
            {
                "Breaches Found": payload.get("breach_count", 0),
                "Lookup Mode": payload.get("lookup_mode", "unknown"),
            },
        )
    )

    breaches = payload.get("breaches", [])
    if breaches:
        lines.append(section_title("Breaches"))
        for breach in breaches:
            verified = "verified" if breach.get("verified") else "unverified"
            summary = (
                f"{breach['name']} ({breach.get('breach_date', 'unknown date')}, "
                f"{verified}, domain: {breach.get('domain', 'unknown')})"
            )
            lines.append(f"- {summary}")
            if breach.get("data_classes"):
                lines.append(f"  Data classes: {', '.join(breach['data_classes'])}")
    else:
        lines.append("No breaches were returned for this email address.")

    if payload.get("warnings"):
        lines.append(format_list_section("Warnings", payload["warnings"]))

    return "\n".join(lines)


def _load_pyhibp() -> Any:
    try:
        import pyhibp
    except ImportError as exc:
        raise OSINTError(
            "pyhibp is not installed. Install dependencies from requirements.txt."
        ) from exc

    return pyhibp


def _configure_hibp(hibp_client: Any, api_key: str, user_agent: str) -> None:
    if hasattr(hibp_client, "set_user_agent"):
        hibp_client.set_user_agent(user_agent)

    if hasattr(hibp_client, "set_api_key"):
        hibp_client.set_api_key(api_key)


def _fetch_account_breaches(hibp_client: Any, address: str) -> list[dict[str, Any]]:
    try:
        return hibp_client.get_account_breaches(address, truncate_response=False)
    except TypeError:
        return hibp_client.get_account_breaches(address)


def _normalize_breach(breach: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": breach.get("Name"),
        "title": breach.get("Title"),
        "domain": breach.get("Domain"),
        "breach_date": breach.get("BreachDate"),
        "added_date": breach.get("AddedDate"),
        "modified_date": breach.get("ModifiedDate"),
        "verified": breach.get("IsVerified"),
        "sensitive": breach.get("IsSensitive"),
        "retired": breach.get("IsRetired"),
        "fabricated": breach.get("IsFabricated"),
        "spam_list": breach.get("IsSpamList"),
        "data_classes": breach.get("DataClasses", []),
    }
