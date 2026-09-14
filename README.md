# Which CDN

A small Flask application that inspects DNS answers, IP ownership, and HTTPS response headers for infrastructure-provider fingerprints. It supports a single domain or a CSV of up to 25 domains.

Results are heuristic: a hosting provider or DNS operator is not necessarily the CDN serving a website. An unknown result means no configured signature matched, not that no CDN exists. The signature list comes from the original 2024 project and is not a complete or current provider directory.

## Run locally

Use Python 3.10 or newer, curl, and optionally whois. Missing whois is reported as unavailable. Linux, macOS, or WSL are recommended; on Windows ensure curl is on PATH.

```sh
python -m venv .venv
# Activate .venv using your shell's activation command.
python -m pip install -r requirements.txt
python project_test/whichcdn.py
```

Open http://127.0.0.1:5000. Submit a bare domain such as www.example.com, without a scheme, port, or path. CSV files must be UTF-8, with domains in the first column and an optional `domain` header. See `examples/domains.csv`.

## What it checks

- DNS response: searches the answer for provider signatures.
- IP ownership: optional whois lookup of the resolved public address.
- HTTPS headers: a HEAD request pinned to the validated IP, without redirects or proxies.
- Timing: curl time to first response byte for that HEAD request; this is not a full page-load benchmark.

HTTPS-only requests and disabled redirects can miss providers that appear only after a redirect. Certificate errors, DNS failures, and timeouts are surfaced as failures rather than successful scans. CSV responses include an error column.

## Tests

```sh
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
```

Tests mock external lookups and cover input validation, public-address restrictions, safe subprocess arguments, fingerprint matching, and CSV isolation/error handling. They do not establish live provider-detection accuracy.

## Scope

Designed for local, trusted use. It has no authentication, user quotas, or production service configuration. Batch requests run sequentially and may take several minutes. DNS and network requests disclose the queried domain to the relevant infrastructure. Do not expose the Flask development server to the internet.

The reviewed version removes shell interpolation, shared uploaded/result files, hardcoded user paths, and debug mode. Campaign data, scan outputs, local configuration, caches, and exploratory scripts are excluded from this cleaned distribution.
