from http.server import BaseHTTPRequestHandler, HTTPServer
import json

from matcher import match_or_create


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/collect":
            data = dict(self.headers)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        if self.path == "/collect":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                payload = {}

            signals = payload.get("signals") or {}
            headers = dict(self.headers)
            ip = (
                headers.get("X-Real-IP")
                or headers.get("x-real-ip")
                or self.client_address[0]
            )

            try:
                result = match_or_create(signals, headers, ip)
                status = 200
            except Exception as e:
                result = {"error": str(e)}
                status = 500

            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, *args, **kwargs):
        pass


if __name__ == "__main__":
    print("finger-backend listening on :3000")
    HTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
