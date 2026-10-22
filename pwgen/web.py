#!/usr/bin/env python3
"""
web.py - browser front end for sync.py.

    python3 web.py --trust-host     first time only: verify and save the NAS host key
    python3 web.py                  serve on http://127.0.0.1:8080
    tailscale serve --bg --https=8443 http://127.0.0.1:8080
                                    then open https://<this-machine>.<tailnet>.ts.net:8443

How it fits together
    * People sign in with their NAS username and password. The server logs in
      to the NAS over SFTP as that person, exactly like sync.py does.
    * Generating happens here: the server encrypts new passwords to the
      person's age public key and appends them to their vault on the NAS.
    * Reading happens in the browser: the Vault page downloads the encrypted
      records and decrypts them with the person's age key on their own device.
      This server never sees a private key, and cannot read stored passwords.

Only the Python standard library, paramiko (via sync.py) and the age tool are
needed. Keep it bound to 127.0.0.1 and put `tailscale serve` in front for HTTPS.

Configuration (flags, or environment variables)
    --host / PWGEN_HOST              NAS hostname or IP       (default 192.168.0.99)
    --port / PWGEN_PORT              NAS SSH port             (default 22)
    --bind / PWGEN_WEB_BIND          address to listen on     (default 127.0.0.1)
    --listen-port / PWGEN_WEB_PORT   port to listen on        (default 8080)
    --cache-dir / PWGEN_WEB_CACHE    server-side cache        (default ~/.local/share/pwgen-web)
    --allow-tailscale-user / PWGEN_WEB_ALLOW
                                     only these Tailscale logins may use the site
                                     (comma-separated in the env var)
    --insecure-cookies               for plain-HTTP testing on another machine only
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import secrets
import sys
import threading
import time
import traceback
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import unquote, urlsplit

import sync

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")

PAGES = {"/login": "login.html", "/generate": "generate.html", "/vault": "vault.html"}
SIGNED_IN_PAGES = {"/generate", "/vault"}
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".woff2": "font/woff2",
    ".svg": "image/svg+xml",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
}

IDLE_TIMEOUT = int(os.environ.get("PWGEN_WEB_IDLE", 15 * 60))      # seconds without a request
MAX_SESSION_AGE = 8 * 3600                                          # sign in again after this
MAX_SESSIONS = 32
MAX_BODY = 64 * 1024
WEB_MAX_COUNT = 50
MIN_LENGTH = sum(n for _, n in sync.MINIMUMS)
MAX_LENGTH = 64
LOGIN_WINDOW = 15 * 60
LOGIN_MAX_FAILURES = 5

SECURITY_HEADERS = {
    # Only this site's own files may load. No inline scripts or styles, no CDNs.
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
        "img-src 'self'; connect-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


class HttpError(Exception):
    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status = status
        self.payload = {"error": message, **extra}


# ─────────────────────────────────────────────
#  SESSIONS
# ─────────────────────────────────────────────
class WebSession:
    """One signed-in browser. Wraps the same VaultSession the CLI uses."""

    def __init__(self, vault: sync.VaultSession, ts_user: Optional[str]):
        self.vault = vault
        self.ts_user = ts_user
        self.lock = threading.Lock()            # one request at a time per session
        self.created = self.last_seen = time.monotonic()
        self.state = "ready"                    # ready | setup | keys_changed
        self.notice: Optional[str] = None
        self.last_sync: Optional[sync.SyncResult] = None
        self.sync_error: Optional[str] = None

    def expired(self, now: float) -> bool:
        return now - self.last_seen > IDLE_TIMEOUT or now - self.created > MAX_SESSION_AGE

    def close(self) -> None:
        with self.lock:
            self.vault.close()
            self.vault.creds.password = None    # drop the NAS password from memory


class SessionStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict = {}

    def create(self, ws: WebSession) -> str:
        self.reap()
        with self._lock:
            if len(self._sessions) >= MAX_SESSIONS:
                raise HttpError(503, "Too many people are signed in. Try again later.")
            token = secrets.token_urlsafe(32)
            self._sessions[token] = ws
            return token

    def get(self, token: Optional[str]) -> Optional[WebSession]:
        if not token:
            return None
        now = time.monotonic()
        with self._lock:
            ws = self._sessions.get(token)
            if ws is None:
                return None
            if ws.expired(now):
                del self._sessions[token]
                expired = ws
            else:
                ws.last_seen = now
                return ws
        expired.close()
        return None

    def remove(self, token: Optional[str]) -> None:
        with self._lock:
            ws = self._sessions.pop(token, None) if token else None
        if ws:
            ws.close()

    def reap(self) -> None:
        now = time.monotonic()
        with self._lock:
            dead = [t for t, ws in self._sessions.items() if ws.expired(now)]
            closing = [self._sessions.pop(t) for t in dead]
        for ws in closing:
            ws.close()


class LoginLimiter:
    """At most LOGIN_MAX_FAILURES wrong passwords per username (and per Tailscale
    user) in LOGIN_WINDOW. Stops anyone guessing NAS passwords through the form."""

    def __init__(self):
        self._lock = threading.Lock()
        self._failures: dict = collections.defaultdict(collections.deque)

    def _trim(self, key: str, now: float) -> collections.deque:
        q = self._failures[key]
        while q and now - q[0] > LOGIN_WINDOW:
            q.popleft()
        return q

    def wait_seconds(self, keys: list) -> int:
        now = time.monotonic()
        with self._lock:
            waits = [LOGIN_WINDOW - (now - q[0]) for q in (self._trim(k, now) for k in keys)
                     if len(q) >= LOGIN_MAX_FAILURES]
        return int(max(waits)) + 1 if waits else 0

    def failure(self, keys: list) -> int:
        """Record a failure; return attempts left before the lockout."""
        now = time.monotonic()
        with self._lock:
            left = LOGIN_MAX_FAILURES
            for k in keys:
                q = self._trim(k, now)
                q.append(now)
                left = min(left, LOGIN_MAX_FAILURES - len(q))
        return max(left, 0)

    def reset(self, keys: list) -> None:
        with self._lock:
            for k in keys:
                self._failures.pop(k, None)


# ─────────────────────────────────────────────
#  THE SERVER
# ─────────────────────────────────────────────
class Config:
    def __init__(self, args):
        self.nas_host = args.host
        self.nas_port = args.port
        self.cache_dir = os.path.expanduser(args.cache_dir)
        self.age_bin = args.age_bin
        self.secure_cookies = not args.insecure_cookies
        self.cookie_name = "__Host-pwgen" if self.secure_cookies else "pwgen"
        allowed = [u.strip().lower() for u in args.allow_tailscale_user if u.strip()]
        self.allowed_ts_users = set(allowed) or None


class PwgenServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, config: Config):
        super().__init__(address, Handler)
        self.config = config
        self.sessions = SessionStore()
        self.limiter = LoginLimiter()
        reaper = threading.Thread(target=self._reap_forever, daemon=True)
        reaper.start()

    def _reap_forever(self):
        while True:
            time.sleep(30)
            self.sessions.reap()


class Handler(BaseHTTPRequestHandler):
    server: PwgenServer

    def version_string(self):
        return "pwgen"                          # don't advertise Python's version

    # ── entry points ────────────────────────
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        path = urlsplit(self.path).path
        try:
            if not self._tailscale_allowed():
                raise HttpError(403, "Your Tailscale account isn't allowed to use this site.")
            if path.startswith("/api/"):
                self._api(method, path)
            elif method != "GET":
                raise HttpError(405, "Method not allowed")
            else:
                self._page(path)
        except HttpError as e:
            if path.startswith("/api/"):
                self._send_json(e.status, e.payload)
            else:
                self._send_text(e.status, e.payload["error"])
        except Exception:
            traceback.print_exc()
            if path.startswith("/api/"):
                self._send_json(500, {"error": "Something went wrong on the server."})
            else:
                self._send_text(500, "Internal error")

    # ── pages and static files ──────────────
    def _page(self, path: str):
        ws = self._session()
        if path == "/":
            return self._redirect("/generate" if ws else "/login")
        if path in PAGES:
            if path in SIGNED_IN_PAGES and not ws:
                return self._redirect("/login")
            if path == "/login" and ws:
                return self._redirect("/generate")
            return self._send_static(PAGES[path])
        if path.startswith("/static/"):
            return self._send_static(unquote(path[len("/static/"):]))
        raise HttpError(404, "Not found")

    def _send_static(self, rel: str):
        parts = rel.split("/")
        if not rel or "\\" in rel or "\x00" in rel or any(p in ("", ".", "..") or p.startswith(".") for p in parts):
            raise HttpError(404, "Not found")
        full = os.path.realpath(os.path.join(STATIC_DIR, *parts))
        ext = os.path.splitext(full)[1].lower()
        if not full.startswith(STATIC_DIR + os.sep) or not os.path.isfile(full) or ext not in MIME_TYPES:
            raise HttpError(404, "Not found")
        with open(full, "rb") as f:
            body = f.read()
        cache = "public, max-age=604800, immutable" if ext == ".woff2" else "no-cache"
        self._send(200, body, MIME_TYPES[ext], {"Cache-Control": cache})

    # ── API ─────────────────────────────────
    def _api(self, method: str, path: str):
        # Cross-site protection: browsers only add this header from our own pages
        # (another site would need CORS permission we never grant), and the
        # session cookie is SameSite=Strict on top of that.
        if self.headers.get("X-Pwgen") != "1":
            raise HttpError(403, "Missing X-Pwgen header.")
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site and fetch_site not in ("same-origin", "none"):
            raise HttpError(403, "Cross-site request refused.")
        route = API_ROUTES.get((method, path))
        if route is None:
            raise HttpError(404 if not any(p == path for _, p in API_ROUTES) else 405, "No such API endpoint.")
        route(self)

    def api_login(self):
        cfg = self.server.config
        data = self._json_body()
        username = str(data.get("username", "")).strip()
        password = data.get("password")
        if not username or not isinstance(password, str) or not password or len(password) > 1024:
            raise HttpError(400, "Enter your username and password.")
        try:
            username = sync.validate_username(username)
        except sync.AuthError:
            raise HttpError(400, "That isn't a valid username.") from None

        ts_user = self._ts_user()
        keys = ["user:" + username.lower()] + (["ts:" + ts_user] if ts_user else [])
        wait = self.server.limiter.wait_seconds(keys)
        if wait:
            raise HttpError(429, f"Too many failed attempts. Try again in {max(1, round(wait / 60))} min.",
                            retryAfter=wait)

        vault = sync.VaultSession(
            cfg.nas_host, cfg.nas_port,
            sync.Credentials(username, password=password, use_default_keys=False, method="password"),
            cache_root=cfg.cache_dir, age_bin=cfg.age_bin, confirm_host_key=None,
        )
        try:
            vault.connect()
        except sync.PasswordLoginDisabled:
            raise HttpError(403, "This account only allows SSH-key login. Use the command-line tool, "
                                 "or an account with a password.") from None
        except sync.AuthError:
            left = self.server.limiter.failure(keys)
            raise HttpError(401, "Wrong username or password.", attemptsLeft=left) from None
        except sync.HostKeyError as e:
            if "CHANGED" in str(e):
                raise HttpError(502, "The NAS host key has changed since it was trusted. Signing in is "
                                     "blocked until someone checks why.") from None
            raise HttpError(502, "The server doesn't trust the NAS yet. On the server, run: "
                                 "python3 web.py --trust-host") from None
        except sync.NasError:
            raise HttpError(503, "Can't reach the NAS right now. Try again in a moment.") from None

        self.server.limiter.reset(keys)
        ws = WebSession(vault, ts_user)
        try:
            with ws.lock:
                self._prepare(ws)
            token = self.server.sessions.create(ws)
        except Exception:
            ws.close()
            raise
        cookie = f"{cfg.cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict"
        if cfg.secure_cookies:
            cookie += "; Secure"
        self._send_json(200, self._status(ws), {"Set-Cookie": cookie})

    def api_info(self):
        """Public: just enough for the sign-in page to say which NAS it signs in to."""
        self._send_json(200, {"nas": self.server.config.nas_host})

    def api_logout(self):
        cfg = self.server.config
        self.server.sessions.remove(self._cookie_token())
        cookie = f"{cfg.cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        if cfg.secure_cookies:
            cookie += "; Secure"
        self._send_json(200, {"ok": True}, {"Set-Cookie": cookie})

    def api_status(self):
        ws = self._require_session()
        with ws.lock:
            self._send_json(200, self._status(ws))

    def api_setup(self):
        """First sign-in: save the person's age public key(s) to their NAS home."""
        ws = self._require_session()
        data = self._json_body()
        text = data.get("recipients")
        if not isinstance(text, str) or len(text) > 8192:
            raise HttpError(400, "Paste your age public key.")
        with ws.lock:
            if ws.state != "setup":
                raise HttpError(409, "Your public key is already set up.")
            try:
                recipients = sync.parse_recipients(text)
                if any(r.startswith("ssh-") for r in recipients):
                    raise sync.VaultError("use an age1… key here; the browser can't decrypt to SSH keys")
                ws.vault.set_recipients(recipients)
            except sync.VaultError as e:
                raise HttpError(400, f"That key doesn't look right: {e}.") from None
            except sync.AgeError as e:
                raise HttpError(400, f"age rejected that key: {e}") from None
            except sync.NasError:
                raise HttpError(503, "Can't reach the NAS to save your key. Try again.") from None
            ws.notice = None
            self._prepare(ws)
            self._send_json(200, self._status(ws))

    def api_accept_keys(self):
        """The public keys on the NAS changed; the person confirmed it was them."""
        ws = self._require_session()
        with ws.lock:
            if ws.state != "keys_changed":
                raise HttpError(409, "Nothing to confirm.")
            ws.vault.accept_recipient_change()
            ws.state = "ready"
            self._sync(ws)
            self._send_json(200, self._status(ws))

    def api_generate(self):
        ws = self._require_session()
        data = self._json_body()
        count, length, label = data.get("count"), data.get("length", sync.DEFAULT_LENGTH), data.get("label", "")
        if type(count) is not int or not 1 <= count <= WEB_MAX_COUNT:
            raise HttpError(400, f"Choose between 1 and {WEB_MAX_COUNT} passwords.")
        if type(length) is not int or not MIN_LENGTH <= length <= MAX_LENGTH:
            raise HttpError(400, f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")
        if not isinstance(label, str):
            raise HttpError(400, "Label must be text.")
        with ws.lock:
            if ws.state != "ready":
                raise HttpError(409, "Finish setting up your key first.")
            passwords = sync.generate_batch(count, length)
            try:
                result = ws.vault.add_passwords(passwords, label)
            except sync.AgeError as e:
                raise HttpError(500, f"Encryption failed: {e}") from None
            self._send_json(200, {
                "passwords": passwords,
                "label": sync.clean_label(label),
                "savedToNas": result.on_nas,
                "error": result.error,
                "status": self._status(ws),
            })

    def api_vault(self):
        """Encrypted records for the browser to decrypt. Nothing here is readable without the key."""
        ws = self._require_session()
        with ws.lock:
            try:
                records, damaged = ws.vault.read_vault(from_nas=True)
                source = "nas"
            except sync.NasError:
                records, damaged = ws.vault.read_vault(from_nas=False)
                source = "cache"
            self._send_json(200, {
                "records": [{"id": rid, "armored": text.split("\n", 1)[1]} for rid, text in records.items()],
                "damaged": damaged,
                "source": source,
            })

    # ── helpers ─────────────────────────────
    def _prepare(self, ws: WebSession) -> None:
        """After sign-in or setup: check the public keys, then sync."""
        try:
            ws.vault.load_recipients()
        except sync.SetupRequired:
            ws.state = "setup"
            return
        except sync.VaultError as e:
            ws.state, ws.notice = "setup", f"Your key file on the NAS isn't valid ({e}). Paste your key again."
            return
        except sync.NasError:
            raise HttpError(503, "Can't reach the NAS right now. Try again in a moment.") from None
        if ws.vault.recipients_added or ws.vault.recipients_removed:
            ws.state = "keys_changed"
            return
        ws.state = "ready"
        self._sync(ws)

    def _sync(self, ws: WebSession) -> None:
        try:
            ws.last_sync, ws.sync_error = ws.vault.sync(), None
        except sync.NasError as e:
            ws.sync_error = str(e)

    def _status(self, ws: WebSession) -> dict:
        v = ws.vault
        status = {
            "username": v.username,
            "nas": v.host,
            "state": ws.state,
            "online": v.online,
            "pendingSync": bool(v.needs_sync and ws.state == "ready"),
            "records": v.record_count(),
            "notice": ws.notice,
            "syncError": ws.sync_error,
            "lastSync": None,
            "keyChange": None,
        }
        if ws.last_sync:
            s = ws.last_sync
            status["lastSync"] = {"pulled": s.pulled, "pushed": s.pushed,
                                  "damaged": s.damaged_local + s.damaged_nas}
        if ws.state == "keys_changed":
            status["keyChange"] = {"added": v.recipients_added, "removed": v.recipients_removed}
        return status

    def _ts_user(self) -> Optional[str]:
        # Set by `tailscale serve`; trustworthy only because we listen on 127.0.0.1.
        user = self.headers.get("Tailscale-User-Login")
        return user.strip().lower() if user else None

    def _tailscale_allowed(self) -> bool:
        allowed = self.server.config.allowed_ts_users
        return allowed is None or self._ts_user() in allowed

    def _cookie_token(self) -> Optional[str]:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = SimpleCookie(raw)
        except CookieError:
            return None
        morsel = jar.get(self.server.config.cookie_name)
        return morsel.value if morsel else None

    def _session(self) -> Optional[WebSession]:
        ws = self.server.sessions.get(self._cookie_token())
        if ws and ws.ts_user != self._ts_user():
            return None                          # cookie used from a different Tailscale account
        return ws

    def _require_session(self) -> WebSession:
        ws = self._session()
        if ws is None:
            raise HttpError(401, "Your session has ended. Sign in again.", signedOut=True)
        return ws

    def _json_body(self) -> dict:
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            raise HttpError(415, "Expected JSON.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise HttpError(400, "Bad Content-Length.") from None
        if not 0 < length <= MAX_BODY:
            raise HttpError(413 if length > MAX_BODY else 400, "Request body missing or too large.")
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise HttpError(400, "Request body isn't valid JSON.") from None
        if not isinstance(data, dict):
            raise HttpError(400, "Expected a JSON object.")
        return data

    def _send(self, status: int, body: bytes, content_type: str, headers: Optional[dict] = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in {**SECURITY_HEADERS, **(headers or {})}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: dict, headers: Optional[dict] = None):
        body = json.dumps(payload).encode("utf-8")
        self._send(status, body, "application/json", {"Cache-Control": "no-store", **(headers or {})})

    def _send_text(self, status: int, text: str):
        self._send(status, (text + "\n").encode("utf-8"), "text/plain; charset=utf-8", {"Cache-Control": "no-store"})

    def _redirect(self, location: str):
        self._send(303, b"", "text/plain", {"Location": location, "Cache-Control": "no-store"})


API_ROUTES = {
    ("GET", "/api/info"): Handler.api_info,
    ("POST", "/api/login"): Handler.api_login,
    ("POST", "/api/logout"): Handler.api_logout,
    ("GET", "/api/status"): Handler.api_status,
    ("POST", "/api/setup"): Handler.api_setup,
    ("POST", "/api/keys/accept"): Handler.api_accept_keys,
    ("POST", "/api/generate"): Handler.api_generate,
    ("GET", "/api/vault"): Handler.api_vault,
}


# ─────────────────────────────────────────────
#  FIRST-TIME HOST KEY CHECK
# ─────────────────────────────────────────────
def trust_host(cfg: Config) -> int:
    """Show the NAS host key fingerprint, and save it if you confirm.
    The web server never accepts an unknown key on its own."""
    import paramiko
    known_hosts = os.path.join(cfg.cache_dir, "known_hosts")
    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
    except (OSError, paramiko.SSHException):
        pass
    if os.path.exists(known_hosts):
        client.load_host_keys(known_hosts)
    client.set_missing_host_key_policy(sync._HostKeyPolicy(known_hosts, sync.cli_confirm_host_key))
    try:
        # No credentials on purpose: the host key is checked before any login is tried.
        client.connect(cfg.nas_host, port=cfg.nas_port, username="pwgen-hostkey-check",
                       allow_agent=False, look_for_keys=False, timeout=sync.CONNECT_TIMEOUT)
    except sync.HostKeyError as e:
        print(f"Not trusted: {e}")
        return 1
    except paramiko.BadHostKeyException:
        print(f"The host key for {cfg.nas_host} has CHANGED. Not trusting it.")
        return 1
    except paramiko.SSHException:
        pass                                    # expected: "no authentication methods"
    except OSError as e:
        print(f"Cannot reach {cfg.nas_host}:{cfg.nas_port}: {e}")
        return 1
    finally:
        client.close()
    print(f"The NAS host key is trusted. Saved in {known_hosts}")
    return 0


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    env = os.environ.get
    p = argparse.ArgumentParser(prog="web.py", description="Browser front end for sync.py.")
    p.add_argument("--host", default=sync.DEFAULT_HOST, help="NAS host")
    p.add_argument("--port", type=int, default=sync.DEFAULT_PORT, help="NAS SSH port")
    p.add_argument("--bind", default=env("PWGEN_WEB_BIND", "127.0.0.1"), help="address to listen on")
    p.add_argument("--listen-port", type=int, default=int(env("PWGEN_WEB_PORT", "8080")), help="port to listen on")
    p.add_argument("--cache-dir", default=env("PWGEN_WEB_CACHE", "~/.local/share/pwgen-web"),
                   help="server-side cache of encrypted vaults")
    p.add_argument("--age-bin", default=sync.DEFAULT_AGE_BIN, help="age binary")
    p.add_argument("--allow-tailscale-user", action="append",
                   default=[u for u in env("PWGEN_WEB_ALLOW", "").split(",") if u.strip()],
                   help="only allow this Tailscale login (repeatable)")
    p.add_argument("--insecure-cookies", action="store_true",
                   help="send cookies over plain HTTP (testing from another machine only)")
    p.add_argument("--trust-host", action="store_true", help="verify and save the NAS host key, then exit")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config(args)
    in_container = os.environ.get("PWGEN_IN_CONTAINER") == "1"
    try:
        sync.ensure_private_dir(cfg.cache_dir)
    except OSError as e:
        hint = (" In Docker, the data folder must be owned by the container's user "
                "(see the Dockerfile's chown line)." if in_container else "")
        print(f"error: can't use {cfg.cache_dir}: {e.strerror}.{hint}", file=sys.stderr)
        return 1
    if args.trust_host:
        return trust_host(cfg)
    try:
        sync.find_age(cfg.age_bin)
    except sync.AgeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not os.path.isdir(STATIC_DIR):
        print(f"error: {STATIC_DIR} is missing", file=sys.stderr)
        return 1
    if in_container:
        # Inside a container, 0.0.0.0 is required to be reachable at all. The
        # protection moves to how the port is published on the host.
        print("note: running in a container. Publish the port on the host's loopback only "
              "(docker run -p 127.0.0.1:8080:8080 ...) so only this machine and "
              "`tailscale serve` can reach it.", file=sys.stderr)
    elif args.bind not in ("127.0.0.1", "::1", "localhost"):
        print(f"warning: listening on {args.bind} lets anything on that network reach this page and "
              "try NAS passwords. Prefer 127.0.0.1 with `tailscale serve` in front.", file=sys.stderr)
        if cfg.allowed_ts_users:
            print("warning: the Tailscale allowlist can be faked when not bound to 127.0.0.1.", file=sys.stderr)
    server = PwgenServer((args.bind, args.listen_port), cfg)
    print(f"pwgen web on http://{args.bind}:{args.listen_port}  (NAS {cfg.nas_host}:{cfg.nas_port})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
