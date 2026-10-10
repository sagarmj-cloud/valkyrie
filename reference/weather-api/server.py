# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""A plain REST service with no MCP at all — the kind of internal API most
enterprises already have. Valkyrie exposes one of its endpoints as a tool
through an HTTP adapter manifest; no server code changes, no MCP wrapper."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

FORECAST = {"pleasanton": {"temp_c": 22, "sky": "clear"}, "seattle": {"temp_c": 13, "sky": "rain"}, "pune": {"temp_c": 28, "sky": "haze"}}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/healthz":
            return self._send(200, {"ok": True})
        if self.headers.get("X-API-Key") != "weather-key-123":
            return self._send(401, {"error": "missing or bad X-API-Key"})
        if u.path.startswith("/v1/forecast/"):
            city = u.path.rsplit("/", 1)[-1].lower()
            units = parse_qs(u.query).get("units", ["c"])[0]
            f = FORECAST.get(city)
            if not f:
                return self._send(404, {"error": f"unknown city {city}"})
            temp = f["temp_c"] if units == "c" else round(f["temp_c"] * 9 / 5 + 32)
            return self._send(200, {"city": city, "temp": temp, "units": units, "sky": f["sky"], "station_phone": "+1-555-0199"})
        self._send(404, {"error": "not found"})

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8201), H).serve_forever()
