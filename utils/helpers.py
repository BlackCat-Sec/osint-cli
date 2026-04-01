from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, date, datetime
from email.utils import parseaddr
from typing import Any, Iterable
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

init(autoreset=True)

_COLOR_ENABLED = sys.stdout.isatty()

DEFAULT_REQUEST_HEADERS = {
    "User-Agent": "osint-cli/0.1.0 (+https://example.invalid/osint-cli)",
    "Accept": "application/json, text/plain;q=0.9, */*;q=0.8",
}

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


class OSINTError(RuntimeError):
    """Raised when a lookup cannot be completed safely."""


def build_requests_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(DEFAULT_REQUEST_HEADERS)
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD"}),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def set_color_enabled(enabled: bool) -> None:
    global _COLOR_ENABLED
    _COLOR_ENABLED = enabled and sys.stdout.isatty()


def colorize(text: str, color: str | None = None, bright: bool = False) -> str:
    if not _COLOR_ENABLED or not color:
        return text

    style = Style.BRIGHT if bright else ""
    return f"{style}{color}{text}{Style.RESET_ALL}"


def section_title(text: str) -> str:
    return colorize(text, Fore.CYAN, bright=True)


def status_label(status: str) -> str:
    color = {
        "found": Fore.GREEN,
        "not_found": Fore.YELLOW,
        "unknown": Fore.MAGENTA,
        "error": Fore.RED,
    }.get(status)
    return colorize(status, color, bright=status in {"found", "error"})


def positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Timeout must be a numeric value.") from exc

    if parsed <= 0:
        raise argparse.ArgumentTypeError("Timeout must be greater than zero.")

    return parsed


def normalize_domain(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise OSINTError("A domain name is required.")

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    host = parsed.netloc or parsed.path
    host = host.strip().strip("/").rstrip(".")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise OSINTError(f"Invalid domain name: {value}") from exc

    if not DOMAIN_PATTERN.match(ascii_host):
        raise OSINTError(f"Invalid domain name: {value}")

    return ascii_host


def normalize_email(value: str) -> str:
    candidate = value.strip()
    _, parsed = parseaddr(candidate)
    if not parsed or parsed != candidate or "@" not in parsed:
        raise OSINTError(f"Invalid email address: {value}")
    return parsed.lower()


def normalize_username(value: str) -> str:
    candidate = value.strip()
    if not candidate or any(char.isspace() for char in candidate):
        raise OSINTError("Username must be a non-empty string without spaces.")
    if "/" in candidate or "\\" in candidate:
        raise OSINTError("Username cannot contain path separators.")
    return candidate


def mask_email(email_address: str) -> str:
    local_part, domain = email_address.split("@", 1)
    if len(local_part) <= 2:
        visible_local = f"{local_part[0]}*" if local_part else "*"
    else:
        visible_local = f"{local_part[0]}{'*' * (len(local_part) - 2)}{local_part[-1]}"
    return f"{visible_local}@{domain}"


def normalize_list(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, (str, bytes)):
        values = [value.decode() if isinstance(value, bytes) else value]
    elif isinstance(value, Iterable):
        values = list(value)
    else:
        values = [value]

    normalized: list[str] = []
    seen: set[str] = set()
    for item in values:
        serialized = string_value(item)
        if serialized and serialized not in seen:
            normalized.append(serialized)
            seen.add(serialized)
    return normalized


def to_iso_date(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, list):
        dates = [to_iso_date(item) for item in value]
        dates = [item for item in dates if item]
        return sorted(dates)[0] if dates else None

    if isinstance(value, datetime):
        return value.date().isoformat()

    if isinstance(value, date):
        return value.isoformat()

    return string_value(value)


def string_value(value: Any) -> str | None:
    if value is None:
        return None
    serialized = str(value).strip()
    return serialized or None


def empty_as_unknown(value: Any) -> str:
    return string_value(value) or "Unknown"


def utcnow_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00",
        "Z",
    )


def base_payload(
    command: str,
    query: str,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "command": command,
        "query": query,
        "generated_at": utcnow_iso(),
    }
    if sources:
        payload["sources"] = sources
    return payload


def json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def print_payload(
    payload: dict[str, Any],
    json_output: bool = False,
    renderer: Any | None = None,
) -> None:
    if json_output:
        print(json.dumps(payload, indent=2, default=json_default))
        return

    if renderer is not None:
        print(renderer(payload))
        return

    if payload.get("error"):
        print(f"Error: {payload['error']}")
        return

    print(json.dumps(payload, indent=2, default=json_default))


def error_payload(command: str | None, query: str | None, message: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": False,
        "error": message,
        "generated_at": utcnow_iso(),
    }
    if command:
        payload["command"] = command
    if query:
        payload["query"] = query
    return payload


def format_key_value_section(title: str, values: dict[str, Any]) -> str:
    lines = [section_title(title)]
    for label, value in values.items():
        rendered = value if value is not None else "Unknown"
        lines.append(f"- {label}: {rendered}")
    return "\n".join(lines)


def format_list_section(title: str, values: list[str]) -> str:
    lines = [section_title(title)]
    for value in values:
        lines.append(f"- {value}")
    return "\n".join(lines)


def parse_retry_after(value: str | None, default: int = 2) -> int:
    if value is None:
        return default

    try:
        parsed = int(float(value))
    except (TypeError, ValueError):
        return default

    return max(parsed, 1)
