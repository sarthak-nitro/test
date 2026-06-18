from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import os
import time
import traceback

from matcher import match_or_create

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("finger-backend.http")


def _short(s, n=300):
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + f"...(+{len(s) - n} chars)"


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Requested-With")
        self.send_header("Access-Control-Max-Age", "86400")

    def _client_ip(self):
        h = self.headers
        return (
            h.get("X-Real-IP")
            or h.get("x-real-ip")
            or (h.get("X-Forwarded-For") or "").split(",")[0].strip()
            or self.client_address[0]
        )

    def _log_request_meta(self, method):
        h = self.headers
        log.info(
            "─── %s %s from ip=%s ua=%s ref=%s origin=%s",
            method,
            self.path,
            self._client_ip(),
            _short(h.get("user-agent") or h.get("User-Agent"), 120),
            _short(h.get("referer") or h.get("Referer"), 120),
            _short(h.get("origin") or h.get("Origin"), 80),
        )
        log.debug("headers: %s", dict(h))

    def do_OPTIONS(self):
        self._log_request_meta("OPTIONS")
        log.info(
            "OPTIONS preflight: ACRM=%s ACRH=%s",
            self.headers.get("Access-Control-Request-Method"),
            self.headers.get("Access-Control-Request-Headers"),
        )
        self.send_response(204)
        self._cors()
        self.end_headers()
        log.info("OPTIONS responded 204")

    def do_GET(self):
        self._log_request_meta("GET")
        if self.path == "/collect":
            data = dict(self.headers)
            body = json.dumps(data, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(body)
            log.info("GET /collect responded 200 (%d bytes, %d headers echoed)", len(body), len(data))
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
        log.info("GET %s responded 200 OK", self.path)

    def do_POST(self):
        t0 = time.time()
        self._log_request_meta("POST")
        if self.path != "/collect":
            self.send_response(404)
            self.end_headers()
            log.warning("POST %s responded 404 (unknown path)", self.path)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        log.info("POST body: %d bytes, preview=%s", length, _short(body, 400))

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError as e:
            log.error("invalid JSON body: %s | raw=%s", e, _short(body, 400))
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid json", "detail": str(e)}).encode())
            return

        signals = payload.get("signals") or {}
        headers = dict(self.headers)
        ip = self._client_ip()
        fp_pro_visitor_id = payload.get("fp_pro_visitor_id")
        fp_pro_request_id = payload.get("fp_pro_request_id")
        domain = (payload.get("hostname") or "").strip().lower() or None

        log.info(
            "POST /collect: ip=%s signals=%d payload_keys=%s ja4=%s ja3_hash=%s h2fp_len=%d fp_pro=%s",
            ip,
            len(signals),
            sorted(payload.keys()),
            headers.get("X-JA4") or headers.get("x-ja4"),
            headers.get("X-JA3-Hash") or headers.get("x-ja3-hash"),
            len(headers.get("X-H2FP") or headers.get("x-h2fp") or ""),
            fp_pro_visitor_id or "n/a",
        )
        log.debug("signals keys: %s", sorted(signals.keys()))

        try:
            result = match_or_create(
                signals, headers, ip,
                fp_pro_visitor_id=fp_pro_visitor_id,
                fp_pro_request_id=fp_pro_request_id,
                domain=domain,
            )
            status = 200
            log.info(
                "→ result: browser_id=%s is_new=%s score=%.3f matched=%s candidates=%d visit_id=%s",
                result.get("browser_id"),
                result.get("is_new_browser"),
                result.get("match_score") or 0.0,
                result.get("matched_against"),
                result.get("candidate_count"),
                result.get("visit_id"),
            )
        except Exception as e:
            log.error("match_or_create failed: %s\n%s", e, traceback.format_exc())
            result = {"error": str(e)}
            status = 500

        body_out = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.end_headers()
        self.wfile.write(body_out)
        log.info("POST /collect responded %d in %.1fms (%d bytes)", status, (time.time() - t0) * 1000, len(body_out))

    def log_message(self, *args, **kwargs):
        # silence the default BaseHTTPRequestHandler stderr access log
        # (we have our own structured logs)
        return


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    log.info("finger-backend starting on :%d (log_level=%s)", port, LOG_LEVEL)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
