
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def _get_ssl_info(url: str) -> dict:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return {"present": False}

        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        not_after = cert.get("notAfter")

        return {
            "present": True,
            "common_name": subject.get("commonName"),
            "issuer": issuer.get("commonName"),
            "valid_to": not_after,
            "raw": {
                "subject": subject,
                "issuer": issuer,
            }
        }

    except Exception as e:
        return {
            "present": False,
            "error": str(e)
        }
