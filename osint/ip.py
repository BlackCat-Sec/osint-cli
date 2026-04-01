from __future__ import annotations

import ipaddress
import os
from typing import Any

import requests

from utils.helpers import (
    OSINTError,
    base_payload,
    build_requests_session,
    format_key_value_section,
    format_list_section,
    section_title,
)

IPINFO_URL_TEMPLATE = "https://ipinfo.io/{ip}/json"


def lookup_ip(
    address: str,
    timeout: float = 10.0,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise OSINTError(f"Invalid IP address: {address}") from exc

    classification = _classify_ip(ip)
    if not ip.is_global:
        payload = base_payload(
            command="ip",
            query=ip.compressed,
            sources=["local-classification"],
        )
        payload.update(
            {
                "ip": ip.compressed,
                "version": ip.version,
                "reverse_pointer": ip.reverse_pointer,
                "classification": classification,
                "is_global": False,
                "is_private": ip.is_private,
                "summary": {
                    "lookup_performed": False,
                    "classification": classification,
                },
                "warnings": [
                    "No external lookup was performed because the IP is not globally routable."
                ],
            }
        )
        return payload

    session = session or build_requests_session()
    params: dict[str, str] = {}
    token = os.getenv("IPINFO_TOKEN")
    if token:
        params["token"] = token

    try:
        response = session.get(
            IPINFO_URL_TEMPLATE.format(ip=ip.compressed),
            params=params,
            timeout=timeout,
        )
        if response.status_code == 429:
            raise OSINTError(
                "IPinfo rate limit reached. Retry later or configure IPINFO_TOKEN."
            )
        response.raise_for_status()
        body = response.json()
    except requests.RequestException as exc:
        raise OSINTError(f"IP lookup failed: {exc}") from exc

    payload = base_payload(
        command="ip",
        query=ip.compressed,
        sources=["IPinfo"],
    )
    payload.update(_normalize_ipinfo_response(ip=ip, body=body))
    payload["summary"] = {
        "lookup_performed": True,
        "classification": payload["classification"],
        "country": payload.get("country") or "Unknown",
    }

    warnings: list[str] = []
    if body.get("readme"):
        warnings.append(
            "IPinfo returned a legacy-style response. Configure IPINFO_TOKEN for more predictable access."
        )
    if warnings:
        payload["warnings"] = warnings

    return payload


def render_ip_result(payload: dict[str, Any]) -> str:
    lines = [section_title(f"IP: {payload['query']}")]
    lines.append(
        format_key_value_section(
            "Summary",
            {
                "Classification": payload.get("classification") or "Unknown",
                "Version": payload.get("version") or "Unknown",
                "Global": payload.get("is_global"),
                "ASN": payload.get("asn") or "Unknown",
                "ISP": payload.get("isp") or "Unknown",
            },
        )
    )
    if payload.get("country") or payload.get("city") or payload.get("region"):
        lines.append(
            format_key_value_section(
                "Location",
                {
                    "Country": payload.get("country") or "Unknown",
                    "Region": payload.get("region") or "Unknown",
                    "City": payload.get("city") or "Unknown",
                    "Postal": payload.get("postal") or "Unknown",
                    "Coordinates": payload.get("coordinates") or "Unknown",
                    "Timezone": payload.get("timezone") or "Unknown",
                },
            )
        )
    lines.append(
        format_key_value_section(
            "Network",
            {
                "Hostname": payload.get("hostname") or "Unknown",
                "Reverse Pointer": payload.get("reverse_pointer") or "Unknown",
                "Country Code": payload.get("country_code") or "Unknown",
                "Anycast": payload.get("anycast"),
                "Bogon": payload.get("bogon"),
            },
        )
    )

    if payload.get("warnings"):
        lines.append(format_list_section("Warnings", payload["warnings"]))

    return "\n".join(lines)


def _normalize_ipinfo_response(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    body: dict[str, Any],
) -> dict[str, Any]:
    asn, isp = _extract_asn_and_isp(body)
    return {
        "ip": body.get("ip", ip.compressed),
        "version": ip.version,
        "reverse_pointer": ip.reverse_pointer,
        "classification": _classify_ip(ip),
        "is_global": ip.is_global,
        "is_private": ip.is_private,
        "hostname": body.get("hostname"),
        "city": body.get("city"),
        "region": body.get("region"),
        "country": body.get("country") or body.get("country_name"),
        "country_code": body.get("country_code") or body.get("country"),
        "postal": body.get("postal"),
        "timezone": body.get("timezone"),
        "coordinates": body.get("loc"),
        "asn": asn,
        "isp": isp,
        "as_domain": _extract_as_domain(body),
        "company": _extract_company(body),
        "privacy": body.get("privacy"),
        "anycast": body.get("anycast"),
        "bogon": bool(body.get("bogon", False)),
    }


def _extract_asn_and_isp(body: dict[str, Any]) -> tuple[str | None, str | None]:
    if isinstance(body.get("asn"), dict):
        asn_data = body["asn"]
        return asn_data.get("asn"), asn_data.get("name")

    if body.get("asn") and body.get("as_name"):
        return body.get("asn"), body.get("as_name")

    org_value = body.get("org")
    if not org_value:
        return None, None

    if " " not in org_value:
        return org_value, None

    candidate_asn, candidate_name = org_value.split(" ", 1)
    if candidate_asn.upper().startswith("AS"):
        return candidate_asn, candidate_name.strip()

    return None, org_value


def _extract_as_domain(body: dict[str, Any]) -> str | None:
    if isinstance(body.get("asn"), dict):
        return body["asn"].get("domain")
    return body.get("as_domain")


def _extract_company(body: dict[str, Any]) -> str | None:
    company = body.get("company")
    if isinstance(company, dict):
        return company.get("name")
    return None


def _classify_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str:
    if ip.is_private:
        return "private"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    return "global"
