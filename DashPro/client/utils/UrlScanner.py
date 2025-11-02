from __future__ import annotations
import os, sys, time, subprocess, threading, argparse
from typing import Optional

# -------------------------
# Embedded UrlScanner (single-file)
# -------------------------
class UrlScanner:
    """
    Tiny in-process scanner:
    - scan_url(url) -> dict or None
    - get_alerts(), flush_alerts_to_file()
    Keep this extremely fast. If you need slow checks, implement a queue/worker.
    """
    def __init__(self, ttl_seconds: int = 30):
        import re
        self.ttl = ttl_seconds
        self._cache = {}             # url -> (ts, result)
        self._lock = threading.Lock()
        self.alert_queue = []
        # simple rules
        self.blocklist = {"malicious-example.test", "badsite.local"}
        self.suspicious_path_regexes = [
            re.compile(r"/(?:download|install|payload)", re.I),
            re.compile(r"(?:exec|run)\b", re.I),
        ]

    # tiny TTL cache helpers
    def _get_cached(self, url: str):
        with self._lock:
            v = self._cache.get(url)
            if not v:
                return None
            ts, res = v
            if time.time() - ts > self.ttl:
                del self._cache[url]
                return None
            return res

    def _set_cached(self, url: str, res):
        with self._lock:
            self._cache[url] = (time.time(), res)

    # core detection (fast, no I/O)
    def analyze_url(self, url: str) -> Optional[dict]:
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            host = (p.hostname or "").lower()
            path = p.path or ""
        except Exception:
            return None

        if host in self.blocklist:
            return {"flag": "blocklist", "confidence": 0.99, "reason": "blocklist", "host": host}

        for rx in self.suspicious_path_regexes:
            if rx.search(path):
                return {"flag": "suspicious_path", "confidence": 0.7, "reason": "path_regex", "match": rx.pattern}

        if host.count(".") >= 3:
            return {"flag": "suspicious_subdomain", "confidence": 0.45, "reason": "many_subdomains", "host": host}

        return None

    # public API
    def scan_url(self, url: str) -> Optional[dict]:
        cached = self._get_cached(url)
        if cached is not None:
            return cached
        try:
            res = self.analyze_url(url)
        except Exception:
            res = None
        self._set_cached(url, res)
        if res:
            alert = {"url": url, "timestamp": int(time.time()), "result": res, "source": "mitm_onefile"}
            with self._lock:
                self.alert_queue.append(alert)
        return res

    def get_alerts(self):
        with self._lock:
            return list(self.alert_queue)

    def flush_alerts_to_file(self, filename: Optional[str] = None):
        if filename is None:
            filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), "urlscanner_alerts.jsonl")
        with self._lock:
            if not self.alert_queue:
                return
            try:
                with open(filename, "a", encoding="utf-8") as f:
                    for a in self.alert_queue:
                        import json
                        f.write(json.dumps(a) + "\n")
            except Exception:
                pass
            self.alert_queue.clear()

# create single shared scanner instance used by addon
_scanner = UrlScanner()

# -------------------------
# mitmproxy addon (keeps code minimal & fast)
# -------------------------
# When mitmproxy imports this file as a script, it expects `addons` list.
# We import mitmproxy types lazily so running this file directly (launcher) does not require mitmproxy import until child proc runs.
try:
    from mitmproxy import http  # type: ignore
    _mitm_available = True
except Exception:
    http = None
    _mitm_available = False

class MitmOnefileAddon:
    """Very small mitmproxy addon that logs every full URL and runs the scanner rapidly."""
    def request(self, flow: "http.HTTPFlow") -> None:  # type: ignore[name-defined]
        # Extract pretty_url (scheme://host/path?query)
        try:
            url = flow.request.pretty_url
        except Exception:
            return
        # Log a single concise line
        print("[mitm_onefile] URL:", url)
        # Run scanner quickly. If heavy checks are needed, scanner should queue them.
        try:
            res = _scanner.scan_url(url)
        except Exception as e:
            print("[mitm_onefile] scanner error:", e)
            res = None
        if res:
            # attach metadata so downstream processes can see it (and add a header for visibility)
            flow.metadata.setdefault("mitm_onefile", {})["flag"] = res
            try:
                flow.request.headers["X-UrlScanner-Flag"] = res.get("flag", "suspected")
            except Exception:
                pass

    def done(self):
        # ensure queued alerts are flushed to disk when mitmproxy exits
        try:
            _scanner.flush_alerts_to_file()
        except Exception:
            pass

# module-level addons for mitmproxy
addons = [MitmOnefileAddon()]

# -------------------------
# Launcher: start mitmproxy as a subprocess using same Python
# -------------------------
def launch_mitmproxy(interactive: bool = True, port: int = 8080):
    """
    Spawn mitmproxy in a child process using the same Python interpreter.
    - interactive=True -> mitmproxy TUI
    - interactive=False -> mitmproxy.tools.dump (headless)
    """
    py = sys.executable or "python"
    if interactive:
        module = "mitmproxy"
    else:
        module = "mitmproxy.tools.dump"
    # run the module form: python -u -m <module> -p <port> -s <thisfile>
    cmd = [py, "-u", "-m", module, "-p", str(port), "-s", os.path.basename(__file__)]
    print("[launcher] Starting mitmproxy:", " ".join(cmd))
    # spawn
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # forward child's stdout to our stdout in background thread
    def forward_output():
        try:
            for line in proc.stdout:
                print(line.rstrip())
        except Exception:
            pass
    t = threading.Thread(target=forward_output, daemon=True)
    t.start()
    return proc

def run_launcher(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(prog="mitm_onefile", description="Run mitmproxy with embedded addon (single file).")
    ap.add_argument("--dump", action="store_true", help="Run headless (mitmproxy.tools.dump)")
    ap.add_argument("--port", "-p", type=int, default=8080, help="Port to listen on")
    args = ap.parse_args(argv)

    # Quick check: mitmproxy must be importable in this interpreter to run child
    try:
        import importlib
        importlib.import_module("mitmproxy")
    except Exception as e:
        print("[launcher] ERROR: mitmproxy not importable in this Python interpreter.")
        print("[launcher] Install it into this Python: python -m pip install mitmproxy")
        print("[launcher] Detailed:", e)
        return 2

    proc = launch_mitmproxy(interactive=not args.dump, port=args.port)

    # loop until child exits or user interrupts
    try:
        while True:
            time.sleep(0.5)
            if proc.poll() is not None:
                print("[launcher] mitmproxy exited with code", proc.returncode)
                break
    except KeyboardInterrupt:
        print("[launcher] Keyboard interrupt, terminating mitmproxy...")
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    # child done; ensure scanner flush
    try:
        _scanner.flush_alerts_to_file()
    except Exception:
        pass
    return 0

# -------------------------
# When run as script: start launcher
# -------------------------
if __name__ == "__main__":
    sys.exit(run_launcher())
