from __future__ import annotations

import argparse
import sys
from typing import Any

from osint import __version__
from osint.domain import lookup_domain, render_domain_result
from osint.email import lookup_email, render_email_result
from osint.ip import lookup_ip, render_ip_result
from osint.user import lookup_username, render_user_result
from utils.helpers import (
    OSINTError,
    error_payload,
    positive_timeout,
    print_payload,
    set_color_enabled,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint-cli",
        description="A modular CLI for basic OSINT workflows.",
    )
    _add_common_arguments(parser, suppress_defaults=False)
    parser.add_argument(
        "--version",
        action="version",
        version=f"osint-cli {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="command",
        required=True,
        help="OSINT command to execute.",
    )

    domain_parser = subparsers.add_parser(
        "domain",
        help="Run WHOIS and DNS lookups for a domain.",
        description="Perform WHOIS and DNS record lookups for a domain name.",
    )
    _add_common_arguments(domain_parser, suppress_defaults=True)
    domain_parser.add_argument("name", help="Domain name to inspect, for example: example.com")
    domain_parser.set_defaults(handler=_handle_domain)

    email_parser = subparsers.add_parser(
        "email",
        help="Check whether an email appears in known HIBP breaches.",
        description="Check an email address against HaveIBeenPwned breach records.",
    )
    _add_common_arguments(email_parser, suppress_defaults=True)
    email_parser.add_argument("address", help="Email address to inspect.")
    email_parser.set_defaults(handler=_handle_email)

    user_parser = subparsers.add_parser(
        "user",
        help="Check common services for an observed username.",
        description="Perform lightweight username-presence checks against common platforms.",
    )
    _add_common_arguments(user_parser, suppress_defaults=True)
    user_parser.add_argument("username", help="Username or handle to inspect.")
    user_parser.add_argument(
        "--services",
        help="Comma-separated service slugs to check, for example: github,gitlab,reddit",
    )
    user_parser.set_defaults(handler=_handle_user)

    ip_parser = subparsers.add_parser(
        "ip",
        help="Geolocate an IP address and identify its ASN/ISP.",
        description="Resolve IP geolocation and ASN information via the IPinfo API.",
    )
    _add_common_arguments(ip_parser, suppress_defaults=True)
    ip_parser.add_argument("address", help="IPv4 or IPv6 address to inspect.")
    ip_parser.set_defaults(handler=_handle_ip)

    return parser


def console_main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_color_enabled(not getattr(args, "no_color", False))

    try:
        payload = args.handler(args)
    except OSINTError as exc:
        payload = error_payload(
            command=getattr(args, "command", None),
            query=_query_from_args(args),
            message=str(exc),
        )
        print_payload(payload, json_output=getattr(args, "json", False))
        return 1
    except KeyboardInterrupt:
        payload = error_payload(
            command=getattr(args, "command", None),
            query=_query_from_args(args),
            message="Operation cancelled by user.",
        )
        print_payload(payload, json_output=getattr(args, "json", False))
        return 130

    print_payload(payload, json_output=args.json, renderer=_renderer_for(args.command))
    return 0


def _query_from_args(args: argparse.Namespace) -> str | None:
    for attribute in ("name", "address", "username"):
        value = getattr(args, attribute, None)
        if value:
            return value
    return None


def _renderer_for(command: str) -> Any:
    renderers = {
        "domain": render_domain_result,
        "email": render_email_result,
        "user": render_user_result,
        "ip": render_ip_result,
    }
    return renderers[command]


def _handle_domain(args: argparse.Namespace) -> dict[str, Any]:
    return lookup_domain(args.name, timeout=args.timeout)


def _handle_email(args: argparse.Namespace) -> dict[str, Any]:
    return lookup_email(args.address, timeout=args.timeout)


def _handle_user(args: argparse.Namespace) -> dict[str, Any]:
    return lookup_username(
        args.username,
        timeout=args.timeout,
        services=args.services,
    )


def _handle_ip(args: argparse.Namespace) -> dict[str, Any]:
    return lookup_ip(args.address, timeout=args.timeout)


def main() -> int:
    return console_main(sys.argv[1:])


def _add_common_arguments(
    parser: argparse.ArgumentParser,
    suppress_defaults: bool,
) -> None:
    json_kwargs: dict[str, Any] = {
        "action": "store_true",
        "help": "Render structured JSON output instead of human-readable text.",
    }
    timeout_kwargs: dict[str, Any] = {
        "type": positive_timeout,
        "help": "Network timeout in seconds for supported HTTP/DNS requests (default: 10).",
    }
    no_color_kwargs: dict[str, Any] = {
        "action": "store_true",
        "help": "Disable ANSI colors in human-readable output.",
    }

    if suppress_defaults:
        json_kwargs["default"] = argparse.SUPPRESS
        timeout_kwargs["default"] = argparse.SUPPRESS
        no_color_kwargs["default"] = argparse.SUPPRESS
    else:
        timeout_kwargs["default"] = 10.0

    parser.add_argument("--json", **json_kwargs)
    parser.add_argument("--timeout", **timeout_kwargs)
    parser.add_argument("--no-color", **no_color_kwargs)
