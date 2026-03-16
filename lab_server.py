#!/usr/bin/env python3
"""
Bjorn Chaos Lab -- Web Server
REST API + SSE for managing vulnerable container deployments.
Optional Bearer token authentication via --api-token or BJORNLAB_API_TOKEN env var.
"""

import http.server
import json
import os
import sys
import threading
import queue
import time
import argparse
import logging
import socketserver
from urllib.parse import urlparse, parse_qs
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab_engine import LabEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("lab_server")

# =============================================================================
# GLOBALS
# =============================================================================

engine: Optional[LabEngine] = None
sse_clients: list = []
sse_lock = threading.Lock()
api_token: Optional[str] = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")


def broadcast_event(level: str, message: str):
    event_data = json.dumps({"level": level, "message": message, "ts": time.time()})
    with sse_lock:
        dead = []
        for i, q in enumerate(sse_clients):
            try:
                q.put_nowait(event_data)
            except queue.Full:
                dead.append(i)
        for i in reversed(dead):
            sse_clients.pop(i)


# =============================================================================
# HTTP HANDLER
# =============================================================================

class LabHandler(http.server.BaseHTTPRequestHandler):
    server_version = "BjornChaosLab/2.0"

    def log_message(self, format, *args):
        msg = format % args
        if "/api/events" in msg or "/api/targets" in msg:
            return
        logger.info(f"{self.client_address[0]} - {msg}")

    # -------------------------------------------------------------------------
    # Auth check
    # -------------------------------------------------------------------------

    def _check_auth(self) -> bool:
        """Return True if request is authorized. If no token is set, all requests pass."""
        if not api_token:
            return True
        auth_header = self.headers.get("Authorization", "")
        if auth_header == f"Bearer {api_token}":
            return True
        # Also check query param for SSE (EventSource can't set headers)
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if params.get("token", [None])[0] == api_token:
            return True
        return False

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    # -------------------------------------------------------------------------
    # Routing
    # -------------------------------------------------------------------------

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            if not self._check_auth():
                self._json_response({"error": "Unauthorized"}, 401)
                return

        if path == "/api/status":
            self._handle_status()
        elif path == "/api/targets":
            self._handle_list_targets()
        elif path.startswith("/api/targets/"):
            name = path.split("/api/targets/", 1)[1]
            self._handle_get_target(name)
        elif path == "/api/report":
            self._handle_report()
        elif path == "/api/events":
            self._handle_sse()
        elif path == "/" or path == "/index.html":
            self._serve_file("index.html", "text/html")
        elif path.startswith("/"):
            rel = path.lstrip("/")
            self._serve_file(rel)
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            if not self._check_auth():
                self._json_response({"error": "Unauthorized"}, 401)
                return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._json_response({"error": "Invalid JSON"}, 400)
            return

        if path == "/api/connect":
            self._handle_connect(data)
        elif path == "/api/deploy":
            self._handle_deploy(data)
        elif path == "/api/clean":
            self._handle_clean(data)
        elif path == "/api/delete":
            self._handle_delete(data)
        elif path == "/api/validate":
            self._handle_validate(data)
        elif path == "/api/upload-creds":
            self._handle_upload_creds(data)
        else:
            self._json_response({"error": "Route not found"}, 404)

    # -------------------------------------------------------------------------
    # API Handlers
    # -------------------------------------------------------------------------

    def _handle_status(self):
        global engine
        if engine is None:
            self._json_response({"connected": False, "host": "", "image_exists": False})
            return

        connected = engine._connected
        self._json_response({
            "connected": connected,
            "host": engine.docker_host,
            "network": engine.network,
            "image_exists": connected,
        })

    def _handle_connect(self, data: dict):
        global engine
        host = data.get("host", "").strip()
        user = data.get("user", "").strip()
        password = data.get("password", "").strip()
        network = data.get("network", "macvlan_zombieland").strip()

        if not host or not user or not password:
            self._json_response({"error": "host, user, password required"}, 400)
            return

        if engine:
            engine.disconnect()

        engine = LabEngine(
            docker_host=host, ssh_user=user, ssh_pass=password,
            network=network, event_callback=broadcast_event,
        )

        success = engine.connect()
        if success:
            image_exists = engine.check_image_exists()
            self._json_response({
                "status": "connected", "host": host,
                "network": network, "image_exists": image_exists,
            })
        else:
            self._json_response({"error": "SSH connection failed"}, 500)

    def _handle_deploy(self, data: dict):
        global engine
        if not engine or not engine.is_connected:
            self._json_response({"error": "Not connected"}, 400)
            return

        count = min(int(data.get("count", 1)), 10)
        mode = data.get("mode", "random")
        difficulty = data.get("difficulty", "medium")

        if mode not in ("random", "web", "database", "network", "full"):
            mode = "random"
        if difficulty not in ("easy", "medium", "hard"):
            difficulty = "medium"

        def deploy_thread():
            try:
                engine.deploy_targets(count=count, mode=mode, difficulty=difficulty)
            except Exception as e:
                broadcast_event("error", f"Fatal error: {e}")

        thread = threading.Thread(target=deploy_thread, daemon=True)
        thread.start()

        self._json_response({"status": "deploying", "count": count, "mode": mode, "difficulty": difficulty})

    def _handle_list_targets(self):
        global engine
        if not engine:
            self._json_response([])
            return
        try:
            targets = engine.list_targets()
            self._json_response(targets)
        except Exception:
            try:
                with engine._lock:
                    stored = list(engine.targets.values())
                self._json_response(stored)
            except Exception:
                self._json_response([])

    def _handle_get_target(self, name: str):
        global engine
        if not engine:
            self._json_response({"error": "Not connected"}, 400)
            return
        intel = engine.targets.get(name)
        if intel:
            self._json_response(intel)
        else:
            self._json_response({"error": "Target not found"}, 404)

    def _handle_clean(self, data: dict):
        global engine
        if not engine or not engine.is_connected:
            self._json_response({"error": "Not connected"}, 400)
            return

        def clean_thread():
            engine.clean_all()

        thread = threading.Thread(target=clean_thread, daemon=True)
        thread.start()
        self._json_response({"status": "cleaning"})

    def _handle_delete(self, data: dict):
        global engine
        if not engine or not engine.is_connected:
            self._json_response({"error": "Not connected"}, 400)
            return

        hostname = data.get("hostname", "")
        if not hostname:
            self._json_response({"error": "hostname required"}, 400)
            return

        success = engine.delete_target(hostname)
        self._json_response({"status": "deleted" if success else "error"})

    def _handle_validate(self, data: dict):
        global engine
        if not engine:
            self._json_response({"error": "Not connected"}, 400)
            return

        flag = data.get("flag", "").strip()
        if not flag:
            self._json_response({"error": "flag required"}, 400)
            return

        result = engine.validate_flag(flag)
        if result:
            self._json_response(result)
        else:
            self._json_response({"valid": False, "message": "Invalid flag"})

    def _handle_upload_creds(self, data: dict):
        global engine
        if not engine:
            self._json_response({"error": "Not connected"}, 400)
            return

        ssh_host = data.get("ssh_host", "").strip()
        ssh_user = data.get("ssh_user", "").strip()
        ssh_pass = data.get("ssh_pass", "").strip()
        remote_path = data.get("remote_path", "/home/bjorn/Bjorn/data/input/dictionary/").strip()

        if not ssh_host or not ssh_user or not ssh_pass:
            self._json_response({"error": "ssh_host, ssh_user, ssh_pass required"}, 400)
            return

        def upload_thread():
            result = engine.upload_credentials(ssh_host, ssh_user, ssh_pass, remote_path)
            if not result.get("success"):
                broadcast_event("error", f"Credential upload failed: {result.get('error', 'Unknown error')}")

        thread = threading.Thread(target=upload_thread, daemon=True)
        thread.start()
        self._json_response({"status": "uploading"})

    def _handle_report(self):
        global engine
        if not engine:
            self._json_response({"error": "Not connected"}, 400)
            return

        report = engine.get_report()
        content = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", "attachment; filename=mission_report.json")
        self.send_header("Content-Length", str(len(content)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(content)

    # -------------------------------------------------------------------------
    # SSE
    # -------------------------------------------------------------------------

    def _handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        q = queue.Queue(maxsize=200)
        with sse_lock:
            sse_clients.append(q)

        try:
            self.wfile.write(b": keepalive\n\n")
            self.wfile.flush()

            while True:
                try:
                    event_data = q.get(timeout=15)
                    self.wfile.write(f"data: {event_data}\n\n".encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            pass
        finally:
            with sse_lock:
                try:
                    sse_clients.remove(q)
                except ValueError:
                    pass

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _json_response(self, data, status: int = 200):
        content = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(content)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(content)

    def _serve_file(self, rel_path: str, content_type: Optional[str] = None):
        # Serve from assets/ if path starts with assets/
        if rel_path.startswith("assets/"):
            file_path = os.path.join(BASE_DIR, rel_path)
        else:
            file_path = os.path.join(WEB_DIR, rel_path)
        if not os.path.isfile(file_path):
            self.send_error(404)
            return

        if not content_type:
            ext = os.path.splitext(file_path)[1].lower()
            content_type = {
                ".html": "text/html", ".css": "text/css",
                ".js": "application/javascript", ".json": "application/json",
                ".png": "image/png", ".svg": "image/svg+xml",
                ".ico": "image/x-icon", ".woff2": "font/woff2",
            }.get(ext, "application/octet-stream")

        with open(file_path, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


# =============================================================================
# THREADED SERVER
# =============================================================================

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


# =============================================================================
# MAIN
# =============================================================================

def main():
    global api_token

    parser = argparse.ArgumentParser(description="Bjorn Chaos Lab -- Web Server")
    parser.add_argument("--port", type=int, default=5000, help="Web server port (default: 5000)")
    parser.add_argument("--host", default="", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--api-token", default="", help="Bearer token for API auth (optional)")
    parser.add_argument("--docker-host", default="", help="Docker host IP (auto-connect on startup)")
    parser.add_argument("--docker-user", default="", help="SSH username")
    parser.add_argument("--docker-password", default="", help="SSH password")
    parser.add_argument("--network", default="macvlan_zombieland", help="Docker macvlan network name")

    args = parser.parse_args()

    # API token from args or env
    api_token = args.api_token or os.environ.get("BJORNLAB_API_TOKEN", "")
    if not api_token:
        api_token = None
    else:
        logger.info("API token authentication enabled")

    # Auto-connect if credentials provided
    if args.docker_host and args.docker_user and args.docker_password:
        global engine
        engine = LabEngine(
            docker_host=args.docker_host,
            ssh_user=args.docker_user,
            ssh_pass=args.docker_password,
            network=args.network,
            event_callback=broadcast_event,
        )
        engine.connect()

    server = ThreadedHTTPServer((args.host, args.port), LabHandler)
    logger.info(f"Bjorn Chaos Lab running on http://localhost:{args.port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()
        if engine:
            engine.disconnect()


if __name__ == "__main__":
    main()
