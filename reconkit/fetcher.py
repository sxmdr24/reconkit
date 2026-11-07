"""Fetching HTTP response headers. The only reconkit module that touches the network.

One request per web service: `HEAD /`, retried once as `GET /` (body not read) if the
server answers 405 or 501. Redirects are not followed. TLS certificates are NOT
verified: lab targets usually have self-signed certificates, and we only read headers.
"""

import http.client
import ssl

from . import __version__

DEFAULT_TIMEOUT = 5  # seconds, per request
RETRY_WITH_GET = (405, 501)  # HEAD not allowed / not implemented
DEFAULT_PORTS = {"http": 80, "https": 443}


class _SNIHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection to an IP address that sends a different name for TLS SNI.

    The stdlib uses the connection host for SNI; we connect to the IP nmap scanned
    but want virtual hosts to see the hostname.
    """

    def __init__(self, host, port, *, server_hostname, **kwargs):
        super().__init__(host, port, **kwargs)
        self.server_hostname = server_hostname

    def connect(self):
        http.client.HTTPConnection.connect(self)  # plain TCP connection
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.server_hostname)


def _unverified_tls_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def make_connection(host, port, scheme, hostname=None, timeout=DEFAULT_TIMEOUT):
    """Create (but don't open) a connection to host:port. Tests replace this with a fake."""
    if scheme == "https":
        return _SNIHTTPSConnection(host, port, server_hostname=hostname or host,
                                   timeout=timeout, context=_unverified_tls_context())
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _host_header(host, port, scheme, hostname):
    name = hostname or host
    return name if DEFAULT_PORTS.get(scheme) == port else f"{name}:{port}"


def _request(method, host, port, scheme, hostname, timeout):
    """Send one request for "/" and return (status, headers dict). Never reads the body."""
    conn = make_connection(host, port, scheme, hostname, timeout)
    try:
        conn.request(method, "/", headers={
            "Host": _host_header(host, port, scheme, hostname),
            "User-Agent": f"ReconKit/{__version__}",
            "Accept": "*/*",
        })
        response = conn.getresponse()
        return response.status, dict(response.getheaders())
    finally:
        conn.close()


def fetch_headers(host, port, scheme, hostname=None, timeout=DEFAULT_TIMEOUT):
    """Fetch the response headers of `scheme://host:port/`.

    Returns {"status": int, "headers": dict} or, if the connection or HTTP exchange
    fails, {"error": str}. Only OSError (timeouts, refused connections, TLS errors)
    and http.client.HTTPException are turned into errors; anything else propagates,
    so bugs (and the test network guard) are never silently swallowed.
    """
    try:
        status, headers = _request("HEAD", host, port, scheme, hostname, timeout)
        if status in RETRY_WITH_GET:
            status, headers = _request("GET", host, port, scheme, hostname, timeout)
    except (OSError, http.client.HTTPException) as exc:
        message = str(exc)
        return {"error": f"{type(exc).__name__}: {message}" if message else type(exc).__name__}
    return {"status": status, "headers": headers}
