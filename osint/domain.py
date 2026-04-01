from __future__ import annotations

from typing import Any, Callable

import dns.resolver
import whois

from utils.helpers import (
    OSINTError,
    base_payload,
    empty_as_unknown,
    format_key_value_section,
    format_list_section,
    normalize_domain,
    normalize_list,
    section_title,
    string_value,
    to_iso_date,
)

DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


def lookup_domain(
    name: str,
    timeout: float = 10.0,
    resolver: dns.resolver.Resolver | None = None,
    whois_client: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    domain = normalize_domain(name)
    whois_client = whois_client or whois.whois
    resolver = resolver or _build_resolver(timeout)

    warnings: list[str] = []
    whois_data: dict[str, Any] = {}

    try:
        whois_response = whois_client(domain)
        whois_data = _normalize_whois_response(whois_response)
    except Exception as exc:
        warnings.append(f"WHOIS lookup failed: {exc}")

    dns_records = _collect_dns_records(domain, resolver, warnings)

    if not whois_data and not any(dns_records.values()):
        raise OSINTError(f"No WHOIS or DNS data could be retrieved for {domain}.")

    payload = base_payload(
        command="domain",
        query=domain,
        sources=["python-whois", "dnspython"],
    )
    payload["whois"] = whois_data
    payload["dns"] = dns_records
    payload["summary"] = {
        "whois_available": bool(any(whois_data.values())),
        "dns_record_types_with_answers": sum(1 for values in dns_records.values() if values),
        "dns_records_found": sum(len(values) for values in dns_records.values()),
    }

    if warnings:
        payload["warnings"] = warnings

    return payload


def render_domain_result(payload: dict[str, Any]) -> str:
    lines = [section_title(f"Domain: {payload['query']}")]

    whois_data = payload.get("whois") or {}
    if whois_data:
        lines.append(
            format_key_value_section(
                "WHOIS",
                {
                    "Registrar": empty_as_unknown(whois_data.get("registrar")),
                    "Created": empty_as_unknown(whois_data.get("creation_date")),
                    "Updated": empty_as_unknown(whois_data.get("updated_date")),
                    "Expires": empty_as_unknown(whois_data.get("expiration_date")),
                },
            )
        )
        if whois_data.get("nameservers"):
            lines.append(format_list_section("Name Servers", whois_data["nameservers"]))
        if whois_data.get("status"):
            lines.append(format_list_section("Statuses", whois_data["status"]))

    dns_data = payload.get("dns") or {}
    lines.append(section_title("DNS Records"))
    for record_type in DNS_RECORD_TYPES:
        values = dns_data.get(record_type, [])
        display = ", ".join(values) if values else "No records"
        lines.append(f"- {record_type}: {display}")

    if payload.get("warnings"):
        lines.append(format_list_section("Warnings", payload["warnings"]))

    return "\n".join(lines)


def _build_resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _collect_dns_records(
    domain: str,
    resolver: dns.resolver.Resolver,
    warnings: list[str],
) -> dict[str, list[str]]:
    dns_records: dict[str, list[str]] = {}

    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            dns_records[record_type] = sorted(_clean_dns_value(answer.to_text()) for answer in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            dns_records[record_type] = []
        except dns.resolver.NXDOMAIN as exc:
            raise OSINTError(f"{domain} does not resolve: {exc}") from exc
        except dns.resolver.LifetimeTimeout:
            warnings.append(f"DNS query timed out while requesting {record_type} records.")
            dns_records[record_type] = []
        except Exception as exc:
            warnings.append(f"DNS lookup for {record_type} failed: {exc}")
            dns_records[record_type] = []

    return dns_records


def _normalize_whois_response(response: Any) -> dict[str, Any]:
    nameservers = normalize_list(_extract_field(response, "name_servers", "nameservers"))
    statuses = normalize_list(_extract_field(response, "status"))

    return {
        "registrar": string_value(_extract_field(response, "registrar")),
        "creation_date": to_iso_date(_extract_field(response, "creation_date")),
        "updated_date": to_iso_date(_extract_field(response, "updated_date")),
        "expiration_date": to_iso_date(_extract_field(response, "expiration_date")),
        "nameservers": nameservers,
        "status": statuses,
    }


def _extract_field(response: Any, *keys: str) -> Any:
    for key in keys:
        if hasattr(response, "get"):
            value = response.get(key)
            if value:
                return value

        if hasattr(response, key):
            value = getattr(response, key)
            if value:
                return value

    return None


def _clean_dns_value(value: str) -> str:
    stripped = value.strip()
    if stripped.endswith(".") and " " not in stripped:
        return stripped[:-1]
    return stripped
