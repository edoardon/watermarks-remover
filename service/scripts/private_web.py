"""Private browser client layered over the unchanged upstream API."""
import hmac
import os
from pathlib import Path
from urllib.parse import urlparse

import server


class PrivateHandler(server.Handler):
    def _authorized(self):
        return bool(server.API_KEY) and hmac.compare_digest(
            self.headers.get("Authorization", ""), "Bearer " + server.API_KEY
        )

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        super().end_headers()

    def do_GET(self):
        if urlparse(self.path).path == "/":
            data = Path(__file__).with_name("private_web.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        else:
            super().do_GET()


if __name__ == "__main__":
    if not os.environ.get("WATERMARKS_SERVER_API_KEY", "").strip():
        raise SystemExit("WATERMARKS_SERVER_API_KEY is required for private access")
    server.Handler = PrivateHandler
    raise SystemExit(server.main())
