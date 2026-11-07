"""Security header analysis for web findings.

This module never touches the network. `analyze_headers` is a pure function, and
`check_findings` gets its HTTP access from the `fetch` function passed in.
"""

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)

# Headers that only mean something on a given scheme. Browsers ignore HSTS sent over plain HTTP.
HTTPS_ONLY_HEADERS = ("Strict-Transport-Security",)

WEB_SERVICES = ("http", "https", "http-alt", "http-proxy")


def web_target(finding):
    """Return (scheme, port) if the finding is an open web service, otherwise None."""
    if finding["state"] != "open" or finding["service"] not in WEB_SERVICES:
        return None
    is_tls = finding["service"] == "https" or finding.get("tunnel") == "ssl"
    return ("https" if is_tls else "http"), finding["port"]


def analyze_headers(headers, scheme):
    """Classify the security headers in a response.

    `headers` is a plain dict of header name -> value. Names are matched
    case-insensitively, and an empty or whitespace-only value counts as missing.
    Returns {"missing": [...], "present": [...], "not_applicable": [...]},
    each list in SECURITY_HEADERS order.
    """
    present_names = {name.lower() for name, value in headers.items() if str(value).strip()}
    result = {"missing": [], "present": [], "not_applicable": []}
    for name in SECURITY_HEADERS:
        if scheme != "https" and name in HTTPS_ONLY_HEADERS:
            result["not_applicable"].append(name)
        elif name.lower() in present_names:
            result["present"].append(name)
        else:
            result["missing"].append(name)
    return result


def _get_header(headers, name):
    """Case-insensitive header lookup; None if absent."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def check_findings(findings, fetch=None):
    """Fetch and analyze headers for every open web finding, adding a "headers_check" key.

    `fetch` defaults to reconkit.fetcher.fetch_headers (imported only when needed, so
    this module stays free of network code). `fetch(host, port, scheme, hostname)` must return either
    {"status": int, "headers": dict} or {"error": str}. Redirects are not followed;
    the first response is analyzed and its Location (if any) recorded.
    Findings that aren't web services are left untouched. Returns `findings`.
    """
    if fetch is None:
        from .fetcher import fetch_headers as fetch

    for finding in findings:
        target = web_target(finding)
        if target is None:
            continue
        scheme, port = target
        hostname = finding["hostname"] if finding["hostname"] != "-" else None
        response = fetch(finding["host"], port, scheme, hostname)

        check = {
            "url": f"{scheme}://{hostname or finding['host']}:{port}/",
            "status": None,
            "location": None,
            "missing": [],
            "present": [],
            "not_applicable": [],
            "error": response.get("error"),
        }
        if check["error"] is None:
            headers = response["headers"]
            check["status"] = response["status"]
            check["location"] = _get_header(headers, "Location")
            check.update(analyze_headers(headers, scheme))
        finding["headers_check"] = check
    return findings
