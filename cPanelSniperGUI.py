#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cPanelSniperGUI.py — Web GUI Server for cPanelSniper
Provides a browser-based dashboard at http://localhost:8087

Usage:
  python3 cPanelSniperGUI.py                    # default port 8087
  python3 cPanelSniperGUI.py --port 8080         # custom port
  python3 cPanelSniperGUI.py --host 0.0.0.0      # bind to all interfaces

stdlib only — no pip required.
"""

import sys
import os
import json
import uuid
import time
import threading
import argparse
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from io import StringIO
from datetime import datetime

# ── Ensure cPanelSniper module is importable ─────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import cPanelSniper as sniper

# ══════════════════════════════════════════════════════════
#  SCAN MANAGER — manages background scans & SSE streams
# ══════════════════════════════════════════════════════════
class ScanSession:
    """Holds state for one scan invocation."""
    def __init__(self, scan_id, targets, config):
        self.scan_id    = scan_id
        self.targets    = targets
        self.config     = config
        self.logs       = []
        self.findings   = []
        self.scanned    = 0
        self.complete   = False
        self.cancelled  = False
        self.lock       = threading.Lock()
        self.listeners  = []  # SSE queues

    def add_log(self, msg):
        with self.lock:
            self.logs.append(msg)
            for q in self.listeners:
                q.append(('log', msg))

    def add_finding(self, finding):
        with self.lock:
            self.findings.append(finding)
            for q in self.listeners:
                q.append(('result', json.dumps(finding)))

    def set_progress(self, scanned, vuln):
        with self.lock:
            self.scanned = scanned
            data = json.dumps({"scanned": scanned, "vuln": vuln})
            for q in self.listeners:
                q.append(('progress', data))

    def finish(self):
        with self.lock:
            self.complete = True
            for q in self.listeners:
                q.append(('done', ''))

    def subscribe(self):
        q = []
        with self.lock:
            self.listeners.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.listeners:
                self.listeners.remove(q)


# Global scan registry
_scans = {}
_scans_lock = threading.Lock()


def _log_interceptor(session, original_log):
    """Monkey-patch sniper.log to capture output for GUI."""
    def patched_log(level, msg, target=""):
        # Call original for CLI output
        original_log(level, msg, target)
        # Clean ANSI codes
        import re
        clean = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', f"[{level:>4}] {msg} {target}")
        session.add_log(clean.strip())
    return patched_log


def run_scan_background(session):
    """Run scanner in background thread with log capture."""
    original_log = sniper.log

    # Create args-like object
    class Args:
        def __init__(self, config, targets):
            self.timeout     = config.get('timeout', 15)
            self.threads     = config.get('threads', 10)
            self.hostname    = config.get('hostname', None)
            self.action      = None
            self.passwd      = None
            self.cmd         = None
            self.rate_limit  = 0
            self.target_list = targets
            self.output      = None
            self.no_color    = True

    args = Args(session.config, session.targets)

    # Disable ANSI colors for GUI
    for attr in [x for x in dir(sniper.C) if not x.startswith("_")]:
        setattr(sniper.C, attr, "")

    # Patch logger
    sniper.log = _log_interceptor(session, original_log)

    try:
        scanned = 0
        vuln_count = 0

        for target in session.targets:
            if session.cancelled:
                session.add_log("[INFO] Scan cancelled by user.")
                break

            result = sniper.scan(target, args)
            scanned += 1

            if result.get("vuln") and result.get("finding"):
                session.add_finding(result["finding"])
                vuln_count += 1

            session.set_progress(scanned, vuln_count)

    except Exception as e:
        session.add_log(f"[ERR] Scan error: {str(e)}")
    finally:
        sniper.log = original_log
        # Restore colors
        sniper.C.RED    = "\033[91m"; sniper.C.GREEN  = "\033[92m"
        sniper.C.YELLOW = "\033[93m"; sniper.C.BLUE   = "\033[94m"
        sniper.C.PURPLE = "\033[95m"; sniper.C.CYAN   = "\033[96m"
        sniper.C.BOLD   = "\033[1m";  sniper.C.DIM    = "\033[2m"
        sniper.C.RESET  = "\033[0m";  sniper.C.ORANGE = "\033[38;5;208m"
        session.finish()


def run_post_exploit_action(target_url, action, session_base, token,
                             canonical, param, timeout=15):
    """Run a post-exploit action and return output."""
    scheme, host, port = sniper.parse_target(target_url)
    ctx = (scheme, host, port, canonical, session_base, token, timeout)

    # Capture stdout
    old_stdout = sys.stdout
    sys.stdout = buffer = StringIO()

    # Disable colors
    for attr in [x for x in dir(sniper.C) if not x.startswith("_")]:
        setattr(sniper.C, attr, "")

    try:
        if action == 'list':
            sniper.action_list_accounts(ctx)
        elif action == 'info':
            sniper.action_server_info(ctx)
        elif action == 'version':
            sniper.action_version(ctx)
        elif action == 'cmd' and param:
            sniper.action_exec_cmd(ctx, param)
        elif action == 'passwd' and param:
            sniper.action_change_passwd(ctx, param)
        else:
            return {"error": f"Unknown action: {action}"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        sys.stdout = old_stdout
        # Restore colors
        sniper.C.RED    = "\033[91m"; sniper.C.GREEN  = "\033[92m"
        sniper.C.YELLOW = "\033[93m"; sniper.C.BLUE   = "\033[94m"
        sniper.C.PURPLE = "\033[95m"; sniper.C.CYAN   = "\033[96m"
        sniper.C.BOLD   = "\033[1m";  sniper.C.DIM    = "\033[2m"
        sniper.C.RESET  = "\033[0m";  sniper.C.ORANGE = "\033[38;5;208m"

    import re
    output = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', buffer.getvalue())
    return {"output": output.strip() or "(no output)"}


# ══════════════════════════════════════════════════════════
#  HTTP REQUEST HANDLER
# ══════════════════════════════════════════════════════════
class GUIHandler(BaseHTTPRequestHandler):
    """HTTP handler serving GUI + REST API + SSE."""

    server_version = "cPanelSniperGUI/2.0"

    def log_message(self, format, *args):
        """Suppress default access logs, use custom format."""
        ts = datetime.now().strftime("%H:%M:%S")
        msg = format % args
        print(f"  \033[94m[{ts}]\033[0m {msg}", flush=True)

    # ── Routing ────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path == '/':
            self._serve_file('gui/index.html', 'text/html')
        elif path.startswith('/gui/'):
            self._serve_static(path)
        elif path == '/api/status':
            self._handle_sse(parsed)
        elif path == '/api/results':
            self._handle_results(parsed)
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path == '/api/scan':
            self._handle_scan_start()
        elif path == '/api/action':
            self._handle_action()
        elif path == '/api/stop':
            self._handle_stop()
        else:
            self._send_json(404, {"error": "Not found"})

    # ── Static Files ───────────────────────────────────────
    def _serve_file(self, filepath, content_type):
        full = os.path.join(SCRIPT_DIR, filepath)
        if not os.path.isfile(full):
            self._send_json(404, {"error": "File not found"})
            return
        with open(full, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', f'{content_type}; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(data)

    def _serve_static(self, path):
        # Security: only serve from gui/ directory
        safe = path.lstrip('/').replace('..', '')
        full = os.path.join(SCRIPT_DIR, safe)
        if not os.path.isfile(full):
            self._send_json(404, {"error": "Not found"})
            return
        mime, _ = mimetypes.guess_type(full)
        mime = mime or 'application/octet-stream'
        with open(full, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(data)

    # ── JSON Response ──────────────────────────────────────
    def _send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length)
        return json.loads(raw) if raw else {}

    # ── API: Start Scan ────────────────────────────────────
    def _handle_scan_start(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON: {e}"})
            return

        targets = body.get('targets', [])
        if not targets:
            self._send_json(400, {"error": "No targets provided"})
            return

        scan_id = str(uuid.uuid4())[:8]
        session = ScanSession(scan_id, targets, body)

        with _scans_lock:
            _scans[scan_id] = session

        # Start background thread
        t = threading.Thread(target=run_scan_background, args=(session,),
                           daemon=True)
        t.start()

        self._send_json(200, {"scan_id": scan_id, "targets": len(targets)})

    # ── API: SSE Stream ────────────────────────────────────
    def _handle_sse(self, parsed):
        qs = parse_qs(parsed.query)
        scan_id = qs.get('scan_id', [None])[0]

        with _scans_lock:
            session = _scans.get(scan_id)

        if not session:
            self._send_json(404, {"error": "Scan not found"})
            return

        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        queue = session.subscribe()

        try:
            # Send existing logs first
            with session.lock:
                for log_msg in session.logs:
                    self.wfile.write(f"event: log\ndata: {log_msg}\n\n".encode())
                for f in session.findings:
                    self.wfile.write(f"event: result\ndata: {json.dumps(f)}\n\n".encode())
                if session.scanned > 0:
                    prog = json.dumps({"scanned": session.scanned,
                                       "vuln": len(session.findings)})
                    self.wfile.write(f"event: progress\ndata: {prog}\n\n".encode())
                self.wfile.flush()

            # Stream new events
            while not session.complete or queue:
                if queue:
                    while queue:
                        event_type, data = queue.pop(0)
                        self.wfile.write(f"event: {event_type}\ndata: {data}\n\n".encode())
                    self.wfile.flush()
                else:
                    time.sleep(0.2)

            # Final done event
            self.wfile.write(b"event: done\ndata: \n\n")
            self.wfile.flush()

        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            session.unsubscribe(queue)

    # ── API: Get Results ───────────────────────────────────
    def _handle_results(self, parsed):
        qs = parse_qs(parsed.query)
        scan_id = qs.get('scan_id', [None])[0]

        with _scans_lock:
            session = _scans.get(scan_id)

        if not session:
            self._send_json(404, {"error": "Scan not found"})
            return

        self._send_json(200, {
            "scan_id":  scan_id,
            "complete": session.complete,
            "scanned":  session.scanned,
            "findings": session.findings
        })

    # ── API: Post-Exploit Action ───────────────────────────
    def _handle_action(self):
        try:
            body = self._read_body()
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return

        target    = body.get('target', '')
        action    = body.get('action', '')
        session_b = body.get('session', '')
        token     = body.get('token', '')
        canonical = body.get('canonical', '')
        param     = body.get('param', '')

        if not target or not session_b or not token:
            self._send_json(400, {"error": "Missing target/session/token"})
            return

        result = run_post_exploit_action(target, action, session_b, token,
                                          canonical, param)
        self._send_json(200, result)

    # ── API: Stop Scan ─────────────────────────────────────
    def _handle_stop(self):
        with _scans_lock:
            for s in _scans.values():
                if not s.complete:
                    s.cancelled = True
        self._send_json(200, {"status": "stopped"})


# ══════════════════════════════════════════════════════════
#  SERVER ENTRY POINT
# ══════════════════════════════════════════════════════════
def banner():
    print(f"""
\033[38;5;208m\033[1m  ╔══════════════════════════════════════════════════════╗
  ║          cPanelSniper — Web GUI Server              ║
  ║   CVE-2026-41940  |  CRLF Auth Bypass Scanner       ║
  ╚══════════════════════════════════════════════════════╝\033[0m
""")

def main():
    banner()

    p = argparse.ArgumentParser(description="cPanelSniper GUI Server")
    p.add_argument('--host', default='127.0.0.1',
                   help='Bind address (default: 127.0.0.1)')
    p.add_argument('--port', type=int, default=8087,
                   help='Port (default: 8087)')
    args = p.parse_args()

    server = HTTPServer((args.host, args.port), GUIHandler)
    server.timeout = 0.5

    url = f"http://{args.host}:{args.port}"
    print(f"  \033[92m●\033[0m Server running at \033[1m\033[96m{url}\033[0m")
    print(f"  \033[2mPress Ctrl+C to stop\033[0m\n")

    # Try to auto-open browser
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n  \033[91m●\033[0m Server stopped.")
        server.server_close()

if __name__ == "__main__":
    main()
