# osint-cli

A modular Python CLI for lightweight OSINT (Open-Source Intelligence) workflows. The tool ships with focused subcommands for:

- `domain`: WHOIS and DNS lookups
- `email`: HaveIBeenPwned breach checks
- `user`: username presence checks on common platforms
- `ip`: IP geolocation and ASN/ISP lookup

The project keeps API keys in environment variables, supports human-readable and JSON output, and includes pytest coverage plus a GitHub Actions CI workflow.

## Features

- Pure-Python WHOIS lookups using `python-whois`
- DNS resolution using `dnspython`
- HaveIBeenPwned account breach checks using `pyhibp`
- Direct HIBP HTTP fallback if `pyhibp` breaks or is unavailable
- Username presence checks powered by `requests`
- Parallel username checks with optional per-service filtering
- IP geolocation through the IPinfo API
- Local-only classification for private, loopback, reserved, and link-local IPs
- `--json` output mode for automation or piping into other tools
- Consistent metadata on every JSON response: `ok`, `generated_at`, `sources`, and `summary`
- `--no-color` support for clean non-TTY or log-friendly output
- Cross-platform packaging with a console entrypoint: `osint-cli`

## Architecture

```mermaid
flowchart LR
  A["User Input"] --> B{"Subcommand"}
  B -->|"domain"| C["WHOIS Lookup"]
  B -->|"domain"| D["DNS Query"]
  B -->|"email"| E["HaveIBeenPwned API"]
  B -->|"user"| F["Username Existence Checks"]
  B -->|"ip"| G["IP Geolocation API"]
  C --> H["Aggregate & Format Results"]
  D --> H
  E --> H
  F --> H
  G --> H
  H --> I["Output (CLI/JSON)"]
```

## Installation

1. Install Python 3.11 or newer.
2. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

3. Install the CLI entrypoint:

```bash
python -m pip install .
```

You can also run the tool directly during development:

```bash
python main.py --help
```

## Kali Linux Quick Start

Kali often enforces PEP 668 "externally managed" Python environments, so the safest and least frustrating way to run this project is inside a virtual environment.

Fast path:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
./scripts/setup-kali.sh
source .venv/bin/activate
```

Manual path:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Make-based path:

```bash
make kali
source .venv/bin/activate
```

Why this matters on Kali:

- it avoids breaking system Python packages
- it works cleanly with Kali's package-management protections
- it gives you an `osint-cli` command in the virtual environment
- it keeps API-client dependencies isolated from the rest of the system

## API Keys

Create environment variables before running API-backed commands:

```bash
export HIBP_API_KEY="your_hibp_api_key"
export IPINFO_TOKEN="your_optional_ipinfo_token"
export OSINT_CLI_USER_AGENT="osint-cli/0.1.0 (security-team@example.com)"
```

PowerShell example:

```powershell
$env:HIBP_API_KEY = "your_hibp_api_key"
$env:IPINFO_TOKEN = "your_optional_ipinfo_token"
$env:OSINT_CLI_USER_AGENT = "osint-cli/0.1.0 (security-team@example.com)"
```

Notes:

- `HIBP_API_KEY` is required for the `email` subcommand.
- `IPINFO_TOKEN` is optional, but recommended to avoid tighter anonymous rate limits.
- `OSINT_CLI_USER_AGENT` lets you override the default HIBP user-agent string.

## Usage

General form:

```bash
osint-cli [--json] [--timeout 10] [--no-color] <command> <query>
```

You can also run the package without installing the console script:

```bash
python -m osint --help
```

## How the Tool Works

The CLI is organized around subcommands. Each subcommand follows the same high-level flow:

1. validate and normalize the input
2. perform the lookup using either a Python library or a remote API
3. normalize the returned data into a predictable schema
4. render either human-readable output or structured JSON

Implementation layout:

- [main.py](C:/VsCode/osint-cli/main.py): lightweight entrypoint
- [osint/cli.py](C:/VsCode/osint-cli/osint/cli.py): argument parsing, shared flags, dispatch
- [osint/domain.py](C:/VsCode/osint-cli/osint/domain.py): WHOIS and DNS lookups
- [osint/email.py](C:/VsCode/osint-cli/osint/email.py): HIBP breach checks with fallback logic
- [osint/user.py](C:/VsCode/osint-cli/osint/user.py): public username presence checks
- [osint/ip.py](C:/VsCode/osint-cli/osint/ip.py): IP classification and IPinfo lookups
- [utils/helpers.py](C:/VsCode/osint-cli/utils/helpers.py): shared validation, formatting, retries, and response helpers

Shared design choices:

- all commands produce a consistent JSON envelope
- timeouts are validated before requests run
- API keys come only from environment variables
- non-global IPs are classified locally to avoid leaking internal addresses
- username checks are parallelized for speed
- tests use mocks and fixtures so CI does not depend on live third-party services

### Domain WHOIS + DNS

```bash
osint-cli domain example.com
osint-cli domain example.com --json
```

### Email breach check

```bash
osint-cli email alice@example.com
osint-cli email alice@example.com --json
```

### Username checks

```bash
osint-cli user johndoe
osint-cli user johndoe --timeout 5 --json
osint-cli user johndoe --services github,gitlab
```

### IP geolocation

```bash
osint-cli ip 8.8.8.8
osint-cli ip 203.0.113.45 --json
osint-cli ip 192.168.1.5 --json
```

## Why Use Each Command

### `domain`

Use this when you need quick infrastructure context on a domain.

Why it is useful:

- identifies registrar and key lifecycle dates
- reveals basic DNS footprint such as mail handling and authoritative nameservers
- helps with recon, incident scoping, phishing investigations, and asset triage

How it works:

- normalizes the domain into a safe canonical form
- queries WHOIS with `python-whois`
- queries DNS record types such as `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, and `SOA` with `dnspython`
- aggregates both data sources into one response

Typical investigation scenarios:

- check whether a phishing domain is newly registered
- identify mail routing and nameserver ownership for a suspicious domain
- compare DNS and WHOIS history across multiple assets in a target scope

### `email`

Use this when validating whether an email address has appeared in public breach data.

Why it is useful:

- helps estimate credential exposure risk
- supports incident response and password-reset prioritization
- gives breach names and exposed data classes without dumping sensitive raw datasets

How it works:

- validates the email format
- reads `HIBP_API_KEY` from the environment
- tries `pyhibp` first
- falls back to the official HIBP HTTP endpoint if the library path fails
- masks the local part of the email in human-readable output

Typical investigation scenarios:

- validate whether an employee or target address has known public breach exposure
- prioritize password resets or MFA prompts during incident response
- enrich a larger identity-risk assessment without storing sensitive breach dumps

### `user`

Use this when correlating a handle across common public platforms.

Why it is useful:

- quickly tests whether a username appears reused
- supports profiling, attribution leads, and account-enumeration research
- lets you limit checks to only the services you care about with `--services`

How it works:

- validates the username format
- selects default services or a filtered set from `--services`
- sends HTTP requests to known profile URLs in parallel
- classifies each service result as `found`, `not_found`, `unknown`, or `error`
- returns both per-service details and summary counts

Typical investigation scenarios:

- check whether a handle is reused across public code and social platforms
- build starting points for manual attribution
- quickly validate whether a username appears worth deeper investigation

### `ip`

Use this when you need quick geolocation and network-owner context.

Why it is useful:

- identifies likely country, region, and city
- extracts ASN and ISP ownership clues
- safely classifies non-public IPs locally instead of sending internal addresses to an external API

How it works:

- validates the IP with Python's `ipaddress` module
- classifies private, loopback, link-local, reserved, multicast, and global addresses
- performs an external lookup only for globally routable IPs
- enriches the result with location, ASN, ISP, reverse pointer, and related metadata

Typical investigation scenarios:

- identify likely network owner for a suspicious public IP
- distinguish internal/private addresses from routable targets during triage
- enrich firewall, phishing, or abuse logs with quick geographic and ASN context

## Operational Notes

- `--json` is best for automation, piping into `jq`, or saving structured output.
- `--timeout` is useful when a target or service is slow.
- `--no-color` keeps logs and redirected output clean.
- `user --services` accepts comma-separated slugs such as `github,gitlab,reddit,x`.
- `user --services twitter` also works and maps to `x`.

## Example Human-Readable Output

### Domain

```text
Domain: example.com
WHOIS
- Registrar: RESERVED-Internet Assigned Numbers Authority
- Created: 1995-08-14
- Updated: 2025-08-14
- Expires: 2026-08-13
DNS Records
- A: 93.184.216.34
- AAAA: No records
- MX: 0 .
- NS: a.iana-servers.net, b.iana-servers.net
- TXT: "v=spf1 -all"
- CNAME: No records
- SOA: sns.dns.icann.org. noc.dns.icann.org. 2025081467 7200 3600 1209600 3600
```

### Email

```text
Email: a***e@example.com
Summary
- Breaches Found: 1
- Lookup Mode: pyhibp
Breaches
- Adobe (2013-10-04, verified, domain: adobe.com)
  Data classes: Email addresses, Passwords
```

### User

```text
Username: johndoe
Summary
- Positive matches: 2
- Services checked: 3
Service Checks
- GitHub: found [200]
  URL: https://github.com/johndoe
- GitLab: found [200]
  URL: https://gitlab.com/johndoe
- Reddit: not_found [404]
  URL: https://www.reddit.com/user/johndoe/
```

### IP

```text
IP: 8.8.8.8
Summary
- Classification: global
- Version: 4
- Global: True
- ASN: AS15169
- ISP: Google LLC
Location
- Country: US
- Region: California
- City: Mountain View
- Postal: 94043
- Coordinates: 37.4056,-122.0775
- Timezone: America/Los_Angeles
```

## Example JSON Output

```json
{
  "ok": true,
  "command": "domain",
  "query": "example.com",
  "generated_at": "2026-04-01T08:52:18Z",
  "sources": [
    "python-whois",
    "dnspython"
  ],
  "whois": {
    "registrar": "Example Registrar Inc.",
    "creation_date": "1995-08-13",
    "updated_date": "2024-08-12",
    "expiration_date": "2025-08-12",
    "nameservers": [
      "ns1.example.com",
      "ns2.example.com"
    ],
    "status": [
      "clientTransferProhibited"
    ]
  },
  "dns": {
    "A": [
      "93.184.216.34"
    ],
    "AAAA": [],
    "MX": [
      "10 mail.example.com."
    ],
    "NS": [
      "ns1.example.com",
      "ns2.example.com"
    ],
    "TXT": [],
    "CNAME": [],
    "SOA": []
  },
  "summary": {
    "whois_available": true,
    "dns_record_types_with_answers": 3,
    "dns_records_found": 5
  }
}
```

Every successful JSON response includes:

- `ok`
- `command`
- `query`
- `generated_at`
- `sources`
- command-specific fields
- `summary`

Errors are also structured in JSON mode and include:

- `ok: false`
- `error`
- `generated_at`
- the command and query when available

## JSON Field Reference

### Common fields

- `ok`: whether the command completed successfully
- `command`: the selected subcommand
- `query`: the normalized input that was used
- `generated_at`: UTC timestamp showing when the result was generated
- `sources`: libraries or services used to build the result
- `summary`: compact result summary for scripts and dashboards
- `warnings`: optional notes about fallback behavior, partial failures, or safe-skips

### Domain fields

- `whois.registrar`
- `whois.creation_date`
- `whois.updated_date`
- `whois.expiration_date`
- `whois.nameservers`
- `whois.status`
- `dns.A`, `dns.AAAA`, `dns.MX`, `dns.NS`, `dns.TXT`, `dns.CNAME`, `dns.SOA`

### Email fields

- `masked_query`
- `lookup_mode`
- `breach_count`
- `breach_names`
- `exposed_data_classes`
- `breaches[].name`
- `breaches[].domain`
- `breaches[].breach_date`
- `breaches[].verified`
- `breaches[].data_classes`

### User fields

- `services_requested`
- `available_services`
- `found_count`
- `services[].service`
- `services[].service_slug`
- `services[].url`
- `services[].status`
- `services[].exists`
- `services[].status_code`
- `services[].note`

### IP fields

- `ip`
- `version`
- `reverse_pointer`
- `classification`
- `is_global`
- `is_private`
- `hostname`
- `city`
- `region`
- `country`
- `country_code`
- `postal`
- `timezone`
- `coordinates`
- `asn`
- `isp`
- `as_domain`
- `company`
- `privacy`
- `anycast`
- `bogon`

## Real-World Investigation Workflows

### Triage a suspicious domain

```bash
osint-cli domain suspicious-example.com --json
```

What to look for:

- recent creation date
- unusual registrar patterns
- nameservers that match known cheap hosting or throwaway setups
- mail records that suggest phishing infrastructure

### Assess exposure for a known email

```bash
osint-cli email analyst@example.com --json
```

What to look for:

- breach count
- breach recency
- exposed data classes such as passwords or phone numbers
- whether the exposed identity should trigger password resets or stronger controls

### Correlate a username across public services

```bash
osint-cli user handle123 --services github,gitlab,reddit,x --json
```

What to look for:

- services where the same handle exists
- whether public developer accounts and public social accounts overlap
- whether a profile set is worth manual follow-up

### Enrich a public IP from a log

```bash
osint-cli ip 8.8.8.8 --json
```

What to look for:

- ASN ownership
- ISP or hosting provider
- likely region or country
- whether the address is actually public and routable

## Troubleshooting

### Kali or Debian refuses global pip installs

Use the provided virtual environment workflow:

```bash
./scripts/setup-kali.sh
source .venv/bin/activate
```

### `email` says `HIBP_API_KEY is required`

Set the key first:

```bash
export HIBP_API_KEY="your_hibp_api_key"
```

### `ip` warns that no external lookup was performed

That is expected for private, loopback, link-local, or reserved IPs. The tool intentionally avoids sending non-global addresses to external services.

### Username results show `unknown`

That usually means the target service returned an ambiguous response, redirected in an unexpected way, or applied anti-bot behavior. Treat it as a signal for manual follow-up, not a definitive presence check.

### The Kali setup script fails

Make sure these are available:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

### CI passes but a local Linux machine fails

Check:

- Python version is 3.11+
- virtual environment is active
- dependencies were installed from `requirements.txt`
- required API variables are exported
- outbound network access is available for live lookups

## Commands

### `domain <name>`

Performs:

- WHOIS lookup
- DNS record collection for `A`, `AAAA`, `MX`, `NS`, `TXT`, and `CNAME`

Typical fields:

- registrar
- creation, update, and expiration dates
- nameservers
- DNS record values

### `email <address>`

Performs:

- HaveIBeenPwned account breach lookup

Typical fields:

- breach name
- breach date
- source domain
- verification status
- exposed data classes

### `user <username>`

Performs:

- lightweight HTTP-based presence checks against GitHub, GitLab, Reddit, Keybase, and X
- parallel checks for faster turnaround
- optional `--services` filtering for targeted lookups

Typical fields:

- service name
- profile URL checked
- whether the username appears present, absent, or unknown

### `ip <address>`

Performs:

- IPinfo geolocation lookup
- local classification only for non-global IPs to avoid leaking internal addresses

Typical fields:

- classification
- IP version
- reverse PTR name
- hostname
- city, region, country
- timezone
- ASN
- ISP / network owner

## Testing

Run the unit test suite:

```bash
python -m pytest
```

Run lint checks:

```bash
python -m flake8 osint utils tests main.py
```

The tests rely on dependency injection and mocked responses rather than live network calls. That keeps the suite deterministic and avoids leaking real query data during CI runs.

Useful project shortcuts:

```bash
make install
make test
make lint
```

## Privacy and Security Notes

- The CLI does not persist query data to disk.
- API keys are only read from environment variables.
- Human-readable email output masks the local-part of the address.
- Private, loopback, reserved, link-local, and other non-global IPs are classified locally and are not sent to IPinfo.
- Username checks are heuristic HTTP probes and can be affected by anti-bot protections or service redesigns.

## Limitations

- `pyhibp` is an older dependency, so the email subcommand uses a defensive direct-HTTP fallback if needed.
- Anonymous IPinfo access is rate-limited.
- Some websites may return ambiguous responses for username checks, which are surfaced as `unknown` instead of forcing a false positive.
- WHOIS data quality varies by registrar and TLD.

## Safe Configuration Checklist

- Keep API keys in shell environment variables, not in source files.
- Do not commit `.env` files with real secrets.
- Prefer `--json` when feeding the output into other tools or scripts.
- Treat username checks as heuristics, not proof of identity.
- Use a dedicated virtual environment on Kali and other Debian-based systems.
