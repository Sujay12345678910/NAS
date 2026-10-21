#!/usr/bin/env python3
"""
sync.py - multi-user password generator with an age-encrypted vault on the NAS.

Commands
    generate  (default)  Log in, sync, generate passwords, store them encrypted.
    reveal               Decrypt and list stored passwords (needs your age identity).
    import FILE          Encrypt an old plaintext passwords.txt into the vault.

How it works
    * You log in with your NAS (SSH) account. Your SSH agent and ~/.ssh keys are
      tried first; if none work you are asked for your password.
    * Each user keeps two files in their own NAS home directory:
          ~/.pwgen/recipients.txt   age public key(s) passwords are encrypted to
          ~/.pwgen/vault.age        append-only vault of encrypted records
    * Only public keys are needed to generate. The private key (identity) is
      needed only for `reveal`, so the NAS and this script never hold anything
      that can decrypt your passwords.
    * A per-user encrypted copy is kept locally so you can keep generating while
      the NAS is down. It is pushed on your next successful login.

Requirements
    Python 3.9+ on Linux or macOS, paramiko, and the `age` command-line tool.
        Arch:      sudo pacman -S age python-paramiko
        Debian/Pi: sudo apt install age python3-paramiko

Configuration (environment variables; all optional)
    PWGEN_HOST       NAS hostname or IP           (default 192.168.0.99)
    PWGEN_PORT       SSH port                     (default 22)
    PWGEN_CACHE_DIR  local cache directory        (default ~/.local/share/pwgen)
    PWGEN_AGE_BIN    path to the age binary       (default: age on PATH)
    PWGEN_IDENTITY   age identity file for reveal (no default)
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import posixpath
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

try:
    import paramiko
except ImportError:  # only `reveal` from a local file works without it
    paramiko = None


# ─────────────────────────────────────────────
#  CONSTANTS - the same for every user
# ─────────────────────────────────────────────
DEFAULT_HOST = os.environ.get("PWGEN_HOST", "192.168.0.99")
DEFAULT_PORT = int(os.environ.get("PWGEN_PORT", "22"))
DEFAULT_CACHE_DIR = os.environ.get("PWGEN_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".local", "share", "pwgen"
)
DEFAULT_AGE_BIN = os.environ.get("PWGEN_AGE_BIN", "age")

REMOTE_DIR_NAME = ".pwgen"
VAULT_NAME = "vault.age"
RECIPIENTS_NAME = "recipients.txt"

CONNECT_TIMEOUT = 10        # seconds
KEEPALIVE_INTERVAL = 30     # seconds; stops idle connections being dropped
MAX_LOGIN_ATTEMPTS = 3
MAX_BATCH = 500             # guards against a typo like 50000
MAX_LABEL_LENGTH = 100

DIGITS = "0123456789"
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SYMBOLS = "!@#$%^{}"
DEFAULT_LENGTH = 15
MINIMUMS = ((DIGITS, 1), (LOWERCASE, 2), (UPPERCASE, 2), (SYMBOLS, 3))

RECORD_MAGIC = "pwgen-record v1"
ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----"
ARMOR_END = "-----END AGE ENCRYPTED FILE-----"
RECORD_ID_RE = re.compile(r"^[0-9a-f]{32}$")
RECIPIENT_RE = re.compile(r"^(age1[0-9a-z]+|ssh-ed25519 [A-Za-z0-9+/=]+|ssh-rsa [A-Za-z0-9+/=]+)(\s|$)")

COMMANDS = ("generate", "reveal", "import")


# ─────────────────────────────────────────────
#  ERRORS - the CLI prints these without a traceback
# ─────────────────────────────────────────────
class PwgenError(Exception):
    """Base class for problems the user can act on."""


class AuthError(PwgenError):
    """The NAS rejected the login."""


class PasswordLoginDisabled(AuthError):
    """The NAS does not accept passwords for this account (keys only)."""


class NasError(PwgenError):
    """The NAS could not be reached or a file operation on it failed."""


class HostKeyError(PwgenError):
    """The NAS host key is unknown and was not accepted, or it has changed."""


class AgeError(PwgenError):
    """The age tool is missing or refused to encrypt/decrypt."""


class VaultError(PwgenError):
    """Bad recipients file, bad identity file, or similar."""


class SetupRequired(PwgenError):
    """The user has no age public key on file yet."""


# ─────────────────────────────────────────────
#  PASSWORD GENERATION
# ─────────────────────────────────────────────
_rng = secrets.SystemRandom()   # OS randomness, safe for passwords


def generate_password(length: int = DEFAULT_LENGTH) -> str:
    """Every class meets its minimum, the rest come from all classes, then shuffle.

    Characters may repeat and symbols can land anywhere, so the output has no
    fixed shape for an attacker to exploit.
    """
    minimum = sum(n for _, n in MINIMUMS)
    if length < minimum:
        raise ValueError(f"length must be at least {minimum}")
    chars = [_rng.choice(pool) for pool, n in MINIMUMS for _ in range(n)]
    everything = DIGITS + LOWERCASE + UPPERCASE + SYMBOLS
    chars += [_rng.choice(everything) for _ in range(length - len(chars))]
    _rng.shuffle(chars)
    return "".join(chars)


def generate_batch(count: int, length: int = DEFAULT_LENGTH, seen: Optional[set] = None) -> list:
    """Return `count` passwords, none repeated within `seen` (updated in place)."""
    if not 1 <= count <= MAX_BATCH:
        raise ValueError(f"count must be between 1 and {MAX_BATCH}")
    seen = set() if seen is None else seen
    batch = []
    while len(batch) < count:
        pw = generate_password(length)
        if pw not in seen:
            seen.add(pw)
            batch.append(pw)
    return batch


# ─────────────────────────────────────────────
#  AGE ENCRYPTION (via the age command-line tool)
# ─────────────────────────────────────────────
def find_age(age_bin: str) -> str:
    path = shutil.which(age_bin)
    if not path:
        raise AgeError(
            f"'{age_bin}' not found. Install age (pacman -S age / apt install age) "
            "or point PWGEN_AGE_BIN at it."
        )
    return path


def age_encrypt(age_bin: str, recipients: list, plaintext: bytes) -> str:
    cmd = [age_bin, "--encrypt", "--armor"]
    for recipient in recipients:
        cmd += ["-r", recipient]
    proc = subprocess.run(cmd, input=plaintext, capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise AgeError("age could not encrypt: " + proc.stderr.decode(errors="replace").strip())
    return proc.stdout.decode("ascii")


def age_decrypt(age_bin: str, identity: bytes, armored: str) -> bytes:
    """Decrypt one record. The identity is passed through a pipe, never a temp file."""
    if len(identity) > 60_000:
        raise VaultError("identity file is unexpectedly large")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, identity)          # small enough to fit in the pipe buffer
    finally:
        os.close(write_fd)
    try:
        proc = subprocess.run(
            [age_bin, "--decrypt", "-i", f"/dev/fd/{read_fd}"],
            input=armored.encode("ascii"),
            capture_output=True,
            pass_fds=(read_fd,),
            timeout=30,
        )
    finally:
        os.close(read_fd)
    if proc.returncode != 0:
        raise AgeError(proc.stderr.decode(errors="replace").strip())
    return proc.stdout


def load_identity(age_bin: str, path: str) -> bytes:
    """Read an age identity. Passphrase-protected ones (age -p) are unlocked once,
    in memory, so you are not asked again for every record."""
    path = os.path.expanduser(path)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise VaultError(f"cannot read identity file {path}: {e.strerror}") from None
    if os.stat(path).st_mode & 0o077:
        print(f"warning: {path} is readable by other users; run: chmod 600 {path}", file=sys.stderr)
    if data.startswith(b"age-encryption.org/") or data.lstrip().startswith(ARMOR_BEGIN.encode()):
        # age prompts for the passphrase on the terminal itself
        proc = subprocess.run([age_bin, "--decrypt", path], stdout=subprocess.PIPE)
        if proc.returncode != 0:
            raise VaultError("could not unlock the identity file (wrong passphrase?)")
        data = proc.stdout
    return data


def parse_recipients(text: str) -> list:
    """age public keys, one per line. Blank lines and #comments are ignored."""
    recipients = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = RECIPIENT_RE.match(line)
        if not match:
            raise VaultError(f"not an age or ssh public key: {line[:40]!r}")
        recipients.append(match.group(1))     # drops a trailing ssh key comment
    return recipients


# ─────────────────────────────────────────────
#  VAULT FORMAT
#
#  The vault is append-only text. Each record is:
#      pwgen-record v1 <32 hex id>
#      -----BEGIN AGE ENCRYPTED FILE-----
#      ...
#      -----END AGE ENCRYPTED FILE-----
#  The encrypted payload is JSON: {"v", "id", "created", "label", "password", "source"}.
#  A record cut short by a power cut has no END line and is skipped when read.
# ─────────────────────────────────────────────
def format_record(record_id: str, armored: str) -> str:
    return f"{RECORD_MAGIC} {record_id}\n{armored.strip()}\n"


def parse_vault(text: str) -> tuple:
    """Return ({record_id: record_text}, number_of_damaged_records)."""
    records: dict = {}
    damaged = 0
    current_id = None
    armor: list = []
    in_armor = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(RECORD_MAGIC + " "):
            if current_id is not None:          # previous record never finished
                damaged += 1
            candidate = line[len(RECORD_MAGIC) + 1:].strip()
            current_id = candidate if RECORD_ID_RE.match(candidate) else None
            if current_id is None:
                damaged += 1
            armor, in_armor = [], False
            continue
        if current_id is None:
            continue                            # leftovers of a damaged record
        if not in_armor:
            if line == ARMOR_BEGIN:
                armor, in_armor = [line], True
            elif line:
                damaged += 1
                current_id = None
            continue
        armor.append(line)
        if line == ARMOR_END:
            records.setdefault(current_id, format_record(current_id, "\n".join(armor)))
            current_id, armor, in_armor = None, [], False
    if current_id is not None:
        damaged += 1
    return records, damaged


def _armored_part(record_text: str) -> str:
    return record_text.split("\n", 1)[1]


# ─────────────────────────────────────────────
#  LOCAL FILES (owner-only permissions, never rewritten in place)
# ─────────────────────────────────────────────
def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def ensure_private_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def local_read(path: str) -> str:
    """Missing file -> "". Any other error is raised, never treated as empty."""
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def local_append(path: str, text: str) -> None:
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b"\n":
            text = "\n" + text                  # never glue onto a half-written record
        _write_all(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def local_write_atomic(path: str, text: str) -> None:
    tmp = f"{path}.tmp-{os.getpid()}-{threading.get_ident()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        _write_all(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


# ─────────────────────────────────────────────
#  NAS FILES over SFTP
# ─────────────────────────────────────────────
def _nas_errors() -> tuple:
    errors = (OSError, EOFError, socket.timeout)
    return errors + ((paramiko.SSHException,) if paramiko else ())


def remote_read(sftp, path: str) -> str:
    """Missing file -> "". Any other error is raised, never treated as empty."""
    try:
        with sftp.open(path, "r") as f:
            data = f.read()
    except FileNotFoundError:
        return ""
    return data.decode("utf-8", errors="replace")


def remote_ensure_dir(sftp, path: str) -> None:
    try:
        sftp.stat(path)
    except FileNotFoundError:
        sftp.mkdir(path, mode=0o700)
    sftp.chmod(path, 0o700)


APPEND_CHUNK = 16 * 1024    # below SFTP's 32 KB write-request size
_RECORD_START = re.compile(r"(?m)^(?=" + re.escape(RECORD_MAGIC) + " )")


def _record_aligned_chunks(text: str, limit: int = APPEND_CHUNK) -> list:
    """Split vault text into chunks that each end on a record boundary."""
    chunks, current = [], ""
    for piece in (p for p in _RECORD_START.split(text) if p):
        if current and len(current) + len(piece) > limit:
            chunks.append(current)
            current = ""
        current += piece
    if current:
        chunks.append(current)
    return chunks


def remote_append(sftp, path: str, text: str) -> None:
    """Append records to a NAS file.

    SFTP sends large writes as several 32 KB requests, and two machines appending
    at once could interleave those mid-record. Each request here carries whole
    records only, so concurrent appends can interleave but never corrupt.
    """
    try:
        size = sftp.stat(path).st_size
    except FileNotFoundError:
        size = None
    if size is None:
        with sftp.open(path, "a"):
            pass                                # create empty, lock it down, then write
        sftp.chmod(path, 0o600)
    elif size:
        with sftp.open(path, "r") as f:
            f.seek(size - 1)
            if f.read(1) != b"\n":
                text = "\n" + text
    with sftp.open(path, "a", bufsize=0) as f:  # unbuffered: one request per write()
        for chunk in _record_aligned_chunks(text):
            f.write(chunk.encode("utf-8"))
    sftp.chmod(path, 0o600)


def remote_write_atomic(sftp, path: str, text: str) -> None:
    tmp = path + ".tmp"
    with sftp.open(tmp, "w") as f:
        sftp.chmod(tmp, 0o600)
        f.write(text.encode("utf-8"))
    try:
        sftp.posix_rename(tmp, path)
    except OSError:                             # server lacks the posix-rename extension
        try:
            sftp.remove(path)
        except FileNotFoundError:
            pass
        sftp.rename(tmp, path)


# ─────────────────────────────────────────────
#  SSH LOGIN
# ─────────────────────────────────────────────
@dataclass
class Credentials:
    username: str
    password: Optional[str] = None
    pkey: object = None                         # a loaded paramiko key, if --key was used
    use_default_keys: bool = True               # SSH agent + ~/.ssh/id_* keys
    method: str = "SSH key"


HostKeyConfirm = Callable[[str, str, str], bool]   # (host, key type, fingerprint) -> trust?


def host_key_fingerprint(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class _HostKeyPolicy:
    """Unknown NAS key: ask (terminal) or refuse (no terminal). Never accept silently."""

    def __init__(self, known_hosts_path: str, confirm: Optional[HostKeyConfirm]):
        self.known_hosts_path = known_hosts_path
        self.confirm = confirm

    def missing_host_key(self, client, hostname, key):
        fingerprint = host_key_fingerprint(key)
        if self.confirm is None or not self.confirm(hostname, key.get_name(), fingerprint):
            raise HostKeyError(
                f"host key for {hostname} is not trusted ({key.get_name()} {fingerprint}). "
                "Run sync.py once in a terminal to verify and save it."
            )
        client.get_host_keys().add(hostname, key.get_name(), key)
        client.save_host_keys(self.known_hosts_path)
        os.chmod(self.known_hosts_path, 0o600)


def _key_classes() -> tuple:
    return tuple(cls for cls in (getattr(paramiko, n, None) for n in ("Ed25519Key", "ECDSAKey", "RSAKey")) if cls)


def load_private_key(path: str, ask_passphrase: Optional[Callable[[str], str]] = None):
    """Load an SSH private key of any common type, asking for its passphrase if needed."""
    if paramiko is None:
        raise PwgenError("paramiko is required (pacman -S python-paramiko / apt install python3-paramiko)")
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        raise AuthError(f"key file not found: {path}")
    needs_passphrase = False
    for cls in _key_classes():
        try:
            return cls.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            needs_passphrase = True
        except (paramiko.SSHException, ValueError):
            continue
    if not needs_passphrase:
        raise AuthError(f"{path} is not a supported private key")
    if ask_passphrase is None:
        raise AuthError(f"{path} is passphrase-protected; use ssh-agent instead")
    passphrase = ask_passphrase(path)
    for cls in _key_classes():
        try:
            return cls.from_private_key_file(path, password=passphrase)
        except (paramiko.SSHException, ValueError):
            continue
    raise AuthError(f"could not unlock {path} (wrong passphrase?)")


def open_connection(host: str, port: int, creds: Credentials, known_hosts_path: str,
                    confirm_host_key: Optional[HostKeyConfirm] = None):
    """Return a logged-in SSHClient, or raise AuthError / NasError / HostKeyError."""
    if paramiko is None:
        raise PwgenError("paramiko is required (pacman -S python-paramiko / apt install python3-paramiko)")
    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()          # trust what ~/.ssh/known_hosts already says
    except (OSError, paramiko.SSHException):
        pass
    if os.path.exists(known_hosts_path):
        client.load_host_keys(known_hosts_path)
    client.set_missing_host_key_policy(_HostKeyPolicy(known_hosts_path, confirm_host_key))
    try:
        client.connect(
            host, port=port, username=creds.username,
            password=creds.password, pkey=creds.pkey,
            allow_agent=creds.use_default_keys, look_for_keys=creds.use_default_keys,
            timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT,
        )
    except PwgenError:
        client.close()
        raise
    except paramiko.BadHostKeyException:
        client.close()
        raise HostKeyError(
            f"the host key for {host} has CHANGED since you last connected. That can mean "
            "someone is intercepting the connection. If you reinstalled the NAS on purpose, "
            "remove its old entry from known_hosts and try again."
        ) from None
    except paramiko.BadAuthenticationType as e:
        client.close()
        if creds.password is not None and "password" not in (e.allowed_types or []):
            raise PasswordLoginDisabled(
                f"the NAS does not accept passwords for {creds.username} "
                f"(it allows: {', '.join(e.allowed_types)})"
            ) from None
        raise AuthError(f"login failed for {creds.username}") from None
    except paramiko.AuthenticationException:
        client.close()
        raise AuthError(f"login failed for {creds.username}") from None
    except paramiko.SSHException as e:
        client.close()
        if "No authentication methods available" in str(e):
            raise AuthError("no usable SSH key found") from None
        raise NasError(f"SSH error: {e}") from None
    except (OSError, socket.timeout) as e:
        client.close()
        raise NasError(f"cannot reach {host}:{port} ({e})") from None
    client.get_transport().set_keepalive(KEEPALIVE_INTERVAL)
    return client


# ─────────────────────────────────────────────
#  PER-USER SESSION
#  Everything that depends on who is logged in lives here, so several users
#  can be served by one process without seeing each other's data.
# ─────────────────────────────────────────────
_path_locks: dict = {}
_path_locks_guard = threading.Lock()


def _lock_for(key: str) -> threading.RLock:
    """One lock per vault file, shared by every session in this process."""
    with _path_locks_guard:
        return _path_locks.setdefault(key, threading.RLock())


def safe_path_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", value)
    if cleaned in ("", ".", ".."):
        raise ValueError(f"unusable name: {value!r}")
    return cleaned


def validate_username(username: str) -> str:
    username = username.strip()
    if not username or len(username) > 64 or re.search(r"[\s/\\:\x00-\x1f]", username):
        raise AuthError("invalid username")
    return username


def clean_label(label: Optional[str]) -> str:
    label = re.sub(r"[\x00-\x1f\x7f]", "", label or "").strip()
    return label[:MAX_LABEL_LENGTH]


@dataclass
class SyncResult:
    pulled: int
    pushed: int
    total: int
    damaged_local: int
    damaged_nas: int


@dataclass
class AddResult:
    record_ids: list
    on_nas: bool
    error: Optional[str] = None


@dataclass
class VaultEntry:
    record_id: str
    created: str
    label: str
    password: str
    source: str = "generate"


@dataclass
class VaultSession:
    host: str
    port: int
    creds: Credentials
    cache_root: str = DEFAULT_CACHE_DIR
    age_bin: str = DEFAULT_AGE_BIN
    confirm_host_key: Optional[HostKeyConfirm] = None

    client: object = field(default=None, init=False, repr=False)
    sftp: object = field(default=None, init=False, repr=False)
    recipients: list = field(default_factory=list, init=False)
    recipients_added: list = field(default_factory=list, init=False)
    recipients_removed: list = field(default_factory=list, init=False)
    _pending_recipients: list = field(default_factory=list, init=False)
    needs_sync: bool = field(default=True, init=False)
    last_error: Optional[str] = field(default=None, init=False)
    _authenticated: bool = field(default=False, init=False)

    def __post_init__(self):
        self.username = validate_username(self.creds.username)
        self.age_bin = find_age(self.age_bin)
        host_dir = safe_path_component(f"{self.host}_{self.port}")
        self.local_dir = os.path.join(self.cache_root, host_dir, safe_path_component(self.username))
        self.local_vault = os.path.join(self.local_dir, VAULT_NAME)
        self.local_recipients = os.path.join(self.local_dir, RECIPIENTS_NAME)
        self.known_hosts = os.path.join(self.cache_root, "known_hosts")
        self.remote_dir = self.remote_vault = self.remote_recipients = None
        self._lock = _lock_for(self.local_vault)
        ensure_private_dir(self.cache_root)
        ensure_private_dir(self.local_dir)

    # ── connection ──────────────────────────
    @property
    def online(self) -> bool:
        transport = self.client.get_transport() if self.client else None
        return bool(transport and transport.is_active() and self.sftp)

    def connect(self) -> None:
        self.close()
        client = open_connection(self.host, self.port, self.creds, self.known_hosts, self.confirm_host_key)
        try:
            sftp = client.open_sftp()
            home = sftp.normalize(".")
        except _nas_errors() as e:
            client.close()
            raise NasError(f"SFTP is not available: {e}") from None
        self.client, self.sftp = client, sftp
        self.remote_dir = posixpath.join(home, REMOTE_DIR_NAME)
        self.remote_vault = posixpath.join(self.remote_dir, VAULT_NAME)
        self.remote_recipients = posixpath.join(self.remote_dir, RECIPIENTS_NAME)
        self._authenticated = True
        self.last_error = None

    def _drop_connection(self, error) -> None:
        self.last_error = str(error) or error.__class__.__name__
        self.close()

    def _ensure_online(self) -> bool:
        """Reconnect with the same credentials if the connection dropped mid-session."""
        if self.online:
            return True
        if not self._authenticated:             # offline from the start: never logged in
            return False
        try:
            self.connect()
            return True
        except PwgenError as e:
            self.last_error = str(e)
            return False

    def close(self) -> None:
        for thing in (self.sftp, self.client):
            try:
                if thing:
                    thing.close()
            except Exception:
                pass
        self.sftp = self.client = None

    def has_local_cache(self) -> bool:
        return os.path.exists(self.local_recipients)

    # ── recipients (age public keys) ────────
    def _validate_recipients(self, recipients: list) -> None:
        if not recipients:
            raise VaultError("at least one public key is required")
        age_encrypt(self.age_bin, recipients, b"")   # age itself rejects malformed keys

    def load_recipients(self) -> list:
        """Online: the NAS copy is the source of truth. Offline: the cached copy."""
        cached = parse_recipients(local_read(self.local_recipients))
        if self.online:
            try:
                text = remote_read(self.sftp, self.remote_recipients)
            except _nas_errors() as e:
                self._drop_connection(e)
                raise NasError(f"could not read recipients from the NAS: {e}") from None
            current = parse_recipients(text)
            if not current:
                raise SetupRequired(f"no public key in ~/{REMOTE_DIR_NAME}/{RECIPIENTS_NAME} on the NAS")
            self._validate_recipients(current)
            self.recipients_added = [r for r in current if cached and r not in cached]
            self.recipients_removed = [r for r in cached if r not in current]
            if self.recipients_added or self.recipients_removed:
                # Not trusted until accept_recipient_change(); nothing can be stored meanwhile.
                self._pending_recipients = current
                self.recipients = []
                return current
            local_write_atomic(self.local_recipients, "\n".join(current) + "\n")
        else:
            current = cached
            if not current:
                raise SetupRequired("no cached public key on this machine; log in online once first")
        self.recipients = current
        return current

    def accept_recipient_change(self) -> None:
        """The user confirmed the new public keys; remember them on this machine."""
        if not self._pending_recipients:
            return
        local_write_atomic(self.local_recipients, "\n".join(self._pending_recipients) + "\n")
        self.recipients = self._pending_recipients
        self._pending_recipients = []
        self.recipients_added, self.recipients_removed = [], []

    def set_recipients(self, recipients: list) -> None:
        """First-time setup: save the user's public key(s) to their NAS home."""
        self._validate_recipients(recipients)
        if not self._ensure_online():
            raise NasError("the NAS is needed to save your public key")
        try:
            remote_ensure_dir(self.sftp, self.remote_dir)
            remote_write_atomic(self.sftp, self.remote_recipients, "\n".join(recipients) + "\n")
        except _nas_errors() as e:
            self._drop_connection(e)
            raise NasError(f"could not save recipients: {e}") from None
        local_write_atomic(self.local_recipients, "\n".join(recipients) + "\n")
        self.load_recipients()

    # ── sync ────────────────────────────────
    def sync(self) -> SyncResult:
        """Two-way merge by record ID. Only appends, so nothing can be erased."""
        with self._lock:
            if not self._ensure_online():
                raise NasError(self.last_error or "not connected")
            local_records, damaged_local = parse_vault(local_read(self.local_vault))
            try:
                nas_records, damaged_nas = parse_vault(remote_read(self.sftp, self.remote_vault))
                to_push = [text for rid, text in local_records.items() if rid not in nas_records]
                if to_push:
                    remote_ensure_dir(self.sftp, self.remote_dir)
                    remote_append(self.sftp, self.remote_vault, "".join(to_push))
            except _nas_errors() as e:
                self._drop_connection(e)
                raise NasError(f"sync failed: {e}") from None
            to_pull = [text for rid, text in nas_records.items() if rid not in local_records]
            if to_pull:
                local_append(self.local_vault, "".join(to_pull))
            self.needs_sync = False
            return SyncResult(
                pulled=len(to_pull), pushed=len(to_push),
                total=len(local_records) + len(to_pull),
                damaged_local=damaged_local, damaged_nas=damaged_nas,
            )

    def record_count(self) -> int:
        return len(parse_vault(local_read(self.local_vault))[0])

    # ── storing passwords ───────────────────
    def add_passwords(self, passwords: list, label: str = "", source: str = "generate") -> AddResult:
        """Encrypt and store. Saved locally first; then pushed to the NAS if possible."""
        if self._pending_recipients:
            raise VaultError("the public keys changed and have not been accepted yet")
        if not self.recipients:
            raise SetupRequired("call load_recipients() first")
        label = clean_label(label)
        created = datetime.now(timezone.utc).isoformat(timespec="seconds")
        records = []
        for password in passwords:
            record_id = secrets.token_hex(16)
            payload = json.dumps({
                "v": 1, "id": record_id, "created": created,
                "label": label, "password": password, "source": source,
            }, ensure_ascii=False).encode("utf-8")
            records.append((record_id, format_record(record_id, age_encrypt(self.age_bin, self.recipients, payload))))
        text = "".join(t for _, t in records)
        ids = [rid for rid, _ in records]

        with self._lock:
            local_append(self.local_vault, text)          # durable before anything else
            if not self._ensure_online():
                self.needs_sync = True
                return AddResult(ids, on_nas=False, error=self.last_error or "working offline")
            try:
                if self.needs_sync:
                    self.sync()                           # also pushes these new records
                else:
                    remote_ensure_dir(self.sftp, self.remote_dir)
                    remote_append(self.sftp, self.remote_vault, text)
            except NasError as e:
                self.needs_sync = True
                return AddResult(ids, on_nas=False, error=str(e))
            except _nas_errors() as e:
                self._drop_connection(e)
                self.needs_sync = True
                return AddResult(ids, on_nas=False, error=self.last_error)
        return AddResult(ids, on_nas=True)

    def read_vault(self, from_nas: bool = False) -> tuple:
        """Return (records, damaged) from the NAS or the local cache."""
        if not from_nas:
            return parse_vault(local_read(self.local_vault))
        if not self._ensure_online():
            raise NasError(self.last_error or "not connected")
        try:
            return parse_vault(remote_read(self.sftp, self.remote_vault))
        except _nas_errors() as e:
            self._drop_connection(e)
            raise NasError(f"could not read the vault: {e}") from None


def decrypt_records(age_bin: str, identity: bytes, records: dict) -> tuple:
    """Return (entries sorted oldest first, [(record_id, problem), ...])."""
    entries, problems = [], []
    for record_id, text in records.items():
        try:
            data = json.loads(age_decrypt(age_bin, identity, _armored_part(text)))
        except AgeError:
            problems.append((record_id, "cannot decrypt (encrypted to a different key, or damaged)"))
            continue
        except ValueError:
            problems.append((record_id, "decrypted, but the contents are not valid"))
            continue
        if data.get("id") != record_id:
            problems.append((record_id, "ID mismatch: the record header was altered or copied"))
            continue
        entries.append(VaultEntry(
            record_id=record_id, created=str(data.get("created", "")),
            label=str(data.get("label", "")), password=str(data.get("password", "")),
            source=str(data.get("source", "")),
        ))
    entries.sort(key=lambda e: e.created)
    return entries, problems


def read_plaintext_passwords(path: str) -> tuple:
    """Lines of an old passwords.txt -> (unique passwords in order, skipped count)."""
    with open(os.path.expanduser(path), "r", encoding="utf-8", errors="replace") as f:
        lines = [line.strip() for line in f]
    unique, seen, skipped = [], set(), 0
    for line in lines:
        if not line or line in seen:
            skipped += 1
            continue
        seen.add(line)
        unique.append(line)
    return unique, skipped


# ─────────────────────────────────────────────
#  COMMAND-LINE INTERFACE
#  Everything below talks to the person. The code above only returns data
#  or raises errors, so a web front end can reuse it unchanged.
# ─────────────────────────────────────────────
def _interactive() -> bool:
    return sys.stdin.isatty()


def ask_yes_no(question: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input(question + suffix).strip().lower()
    return default if not answer else answer in ("y", "yes")


def ask_count() -> int:
    while True:
        raw = input("How many passwords would you like to generate? ").strip()
        try:
            count = int(raw)
        except ValueError:
            print("  Please enter a whole number.")
            continue
        if 1 <= count <= MAX_BATCH:
            return count
        print(f"  Please enter a number from 1 to {MAX_BATCH}.")


def cli_confirm_host_key(hostname: str, key_type: str, fingerprint: str) -> bool:
    short = {"ssh-ed25519": "ed25519", "ssh-rsa": "rsa"}.get(key_type, "ecdsa" if "ecdsa" in key_type else key_type)
    print(f"\nThe NAS at {hostname} has not been seen before.")
    print(f"  {key_type} key fingerprint: {fingerprint}")
    print("  To verify, run this on the NAS and compare:")
    print(f"    ssh-keygen -lf /etc/ssh/ssh_host_{short}_key.pub")
    return ask_yes_no("Trust this host key?")


def cli_login(args, allow_offline: bool) -> VaultSession:
    """Ask who you are, try SSH keys, then your password. Returns a session."""
    username = args.user or input("NAS username: ")
    username = validate_username(username)
    confirm = cli_confirm_host_key if _interactive() else None
    common = dict(host=args.host, port=args.port, cache_root=args.cache_dir,
                  age_bin=args.age_bin, confirm_host_key=confirm)

    pkey = None
    if args.key:
        pkey = load_private_key(args.key, lambda p: getpass.getpass(f"Passphrase for {p}: "))
    use_keys = pkey is not None or not args.no_default_keys

    if use_keys:
        session = VaultSession(creds=Credentials(username, pkey=pkey,
                                                 use_default_keys=not args.no_default_keys), **common)
        try:
            session.connect()
            return session
        except AuthError:
            pass                                # no working key -> fall through to password
        except NasError as e:
            return _maybe_offline(session, e, allow_offline, args)

    if not _interactive():
        raise AuthError("key login failed and there is no terminal to ask for a password")
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        password = getpass.getpass(f"Password for {username}@{args.host}: ")
        session = VaultSession(creds=Credentials(username, password=password,
                                                 use_default_keys=False, method="password"), **common)
        try:
            session.connect()
            return session
        except PasswordLoginDisabled:
            raise
        except AuthError:
            remaining = MAX_LOGIN_ATTEMPTS - attempt
            print(f"  Login failed. {remaining} attempt(s) left." if remaining else "  Login failed.")
        except NasError as e:
            return _maybe_offline(session, e, allow_offline, args)
    raise AuthError("too many failed login attempts")


def _maybe_offline(session: VaultSession, error: NasError, allow_offline: bool, args) -> VaultSession:
    print(f"[!] Could not reach the NAS: {error}")
    if not allow_offline:
        raise error
    if not session.has_local_cache():
        raise NasError("the NAS is unreachable and this machine has no cached setup for this user yet")
    if getattr(args, "offline", False) or (_interactive() and ask_yes_no(
            "Continue offline? Passwords are saved on this machine and pushed on your next login.")):
        session.creds.method = "offline"
        return session
    raise error


def cli_setup_recipients(session: VaultSession) -> None:
    print(f"\nNo age public key is set up for {session.username} yet.")
    print("Create one on the machine where you will reveal passwords:")
    print("    age-keygen -o ~/.config/age/pwgen.txt")
    print("Then paste the public key it prints (age1...). You can add backup keys too.")
    print("Press Enter on an empty line when done.")
    lines = []
    while True:
        line = input("  public key: ").strip()
        if not line:
            if lines:
                break
            continue
        try:
            lines += parse_recipients(line)
        except VaultError as e:
            print(f"  {e}")
    session.set_recipients(lines)
    print(f"Saved to ~/{REMOTE_DIR_NAME}/{RECIPIENTS_NAME} on the NAS.")


def cli_prepare(session: VaultSession) -> None:
    """Make sure recipients exist and haven't been swapped, then sync."""
    try:
        session.load_recipients()
    except SetupRequired:
        if not (session.online and _interactive()):
            raise
        cli_setup_recipients(session)

    if session.recipients_added or session.recipients_removed:
        print("\n[!] The public keys on the NAS changed since your last login on this machine:")
        for r in session.recipients_added:
            print(f"    + {r}")
        for r in session.recipients_removed:
            print(f"    - {r}")
        print("    If you didn't change them, stop: new passwords would be readable by whoever holds the new key.")
        if not (_interactive() and ask_yes_no("Continue with the new keys?")):
            raise VaultError("public keys changed; not continuing")
        session.accept_recipient_change()

    print(f"\nWelcome, {session.username}!  ", end="")
    if session.creds.method == "offline":
        print("Working offline.")
        print(f"Vault: {session.record_count()} password(s) cached on this machine.")
        return
    print(f"Logged in with {session.creds.method}.")
    result = session.sync()
    print(f"Vault: {result.total} password(s). Synced: pulled {result.pulled}, pushed {result.pushed}.")
    damaged = result.damaged_local + result.damaged_nas
    if damaged:
        print(f"[!] Ignored {damaged} damaged record(s), probably from an interrupted write.")


def cmd_generate(args) -> int:
    if args.count is not None and not 1 <= args.count <= MAX_BATCH:
        raise PwgenError(f"--count must be between 1 and {MAX_BATCH}")
    if args.count is None and not _interactive():
        raise PwgenError("--count is required when not running in a terminal")
    session = cli_login(args, allow_offline=True)
    try:
        cli_prepare(session)
        seen: set = set()
        session_total = 0
        while True:
            count = args.count if args.count is not None else ask_count()
            if args.label is not None:
                label = args.label
            elif _interactive():
                label = input("Label for this batch (site or account, optional): ")
            else:
                label = ""
            passwords = generate_batch(count, args.length, seen)
            result = session.add_passwords(passwords, label)    # stored before shown

            print()
            for i, password in enumerate(passwords, 1):
                print(f"  [{i:>3}] {password}")
            session_total += len(passwords)
            if result.on_nas:
                print(f"\n  Saved {len(passwords)} to the NAS (encrypted).")
            else:
                print(f"\n  [!] Saved {len(passwords)} on this machine only: {result.error}")
                print("      They will be pushed to the NAS on your next successful login.")
            print(f"  Session total: {session_total}")

            if args.count is not None or not _interactive():
                break
            if not ask_yes_no("\nGenerate more?"):
                break
        print("\nThese are only shown once. Use `sync.py reveal` on a machine with your age key to see them again.")
    finally:
        session.close()
    return 0


def cmd_import(args) -> int:
    passwords, skipped = read_plaintext_passwords(args.file)
    if not passwords:
        raise PwgenError(f"no passwords found in {args.file}")
    session = cli_login(args, allow_offline=True)
    try:
        cli_prepare(session)
        result = None
        for start in range(0, len(passwords), MAX_BATCH):
            result = session.add_passwords(passwords[start:start + MAX_BATCH], args.label, source="import")
        where = "the NAS" if result.on_nas else f"this machine only ({result.error})"
        print(f"\nImported {len(passwords)} password(s) to {where}; skipped {skipped} blank/duplicate line(s).")
        print(f"{args.file} was NOT deleted. Check `sync.py reveal` works first, then remove it yourself.")
    finally:
        session.close()
    return 0


def _format_time(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso[:16]


def cmd_reveal(args) -> int:
    if not args.identity:
        raise PwgenError("give your age identity with --identity PATH (or set PWGEN_IDENTITY)")
    age_bin = find_age(args.age_bin)

    if args.vault:
        records, damaged = parse_vault(local_read(os.path.expanduser(args.vault)))
        source = args.vault
    elif args.from_nas:
        session = cli_login(args, allow_offline=False)
        try:
            records, damaged = session.read_vault(from_nas=True)
        finally:
            session.close()
        source = "the NAS"
    else:
        username = validate_username(args.user or input("NAS username: "))
        local_vault = os.path.join(args.cache_dir, safe_path_component(f"{args.host}_{args.port}"),
                                   safe_path_component(username), VAULT_NAME)
        if not os.path.exists(local_vault):
            raise PwgenError("no local vault for that user on this machine; use --from-nas")
        records, damaged = parse_vault(local_read(local_vault))
        source = "the local cache (use --from-nas for the latest)"

    identity = load_identity(age_bin, args.identity)
    entries, problems = decrypt_records(age_bin, identity, records)
    if args.search:
        needle = args.search.lower()
        entries = [e for e in entries if needle in e.label.lower()]
    if args.last:
        entries = entries[-args.last:]

    print(f"\n{len(entries)} password(s) from {source}:\n")
    if entries:
        width = max(5, min(30, max(len(e.label) for e in entries)))
        print(f"  {'Created':<16}  {'Label':<{width}}  Password")
        for e in entries:
            print(f"  {_format_time(e.created):<16}  {(e.label or '-')[:width]:<{width}}  {e.password}")
    if problems:
        print(f"\n[!] {len(problems)} record(s) could not be shown:")
        for record_id, problem in problems:
            print(f"    {record_id[:8]}  {problem}")
    if damaged:
        print(f"[!] {damaged} damaged record(s) ignored (interrupted writes).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default=DEFAULT_HOST, help=f"NAS host (default {DEFAULT_HOST})")
    common.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"SSH port (default {DEFAULT_PORT})")
    common.add_argument("--user", help="NAS username (asked if omitted)")
    common.add_argument("--key", help="SSH private key file; the agent and ~/.ssh keys are tried anyway")
    common.add_argument("--no-default-keys", action="store_true",
                        help="don't try the SSH agent or ~/.ssh keys")
    common.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, help="local cache directory")
    common.add_argument("--age-bin", default=DEFAULT_AGE_BIN, help="age binary to use")

    parser = argparse.ArgumentParser(
        prog="sync.py",
        description="Generate passwords and keep them in an age-encrypted vault on your NAS.",
        epilog="Run with no command to generate passwords interactively.",
    )
    sub = parser.add_subparsers(dest="command")

    gen = sub.add_parser("generate", parents=[common], help="generate and store passwords (default)")
    gen.add_argument("--count", type=int, help="generate this many and exit (no prompts)")
    gen.add_argument("--label", help="label for the batch, e.g. github or bank")
    gen.add_argument("--length", type=int, default=DEFAULT_LENGTH, help=f"password length (default {DEFAULT_LENGTH})")
    gen.add_argument("--offline", action="store_true", help="if the NAS is unreachable, continue without asking")

    rev = sub.add_parser("reveal", parents=[common], help="decrypt and list stored passwords")
    rev.add_argument("--identity", default=os.environ.get("PWGEN_IDENTITY"),
                     help="age identity (private key) file")
    rev.add_argument("--from-nas", action="store_true", help="read the vault from the NAS (logs in)")
    rev.add_argument("--vault", help="read a specific vault file instead")
    rev.add_argument("--last", type=int, help="show only the newest N")
    rev.add_argument("--search", help="show only labels containing this text")

    imp = sub.add_parser("import", parents=[common], help="encrypt an old plaintext passwords.txt")
    imp.add_argument("file", help="plaintext file, one password per line")
    imp.add_argument("--label", default="imported", help="label for imported passwords")
    imp.add_argument("--offline", action="store_true", help="if the NAS is unreachable, continue without asking")
    return parser


def main(argv: Optional[list] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help")):
        argv.insert(0, "generate")
    args = build_parser().parse_args(argv)
    if getattr(args, "length", DEFAULT_LENGTH) < sum(n for _, n in MINIMUMS):
        print(f"error: --length must be at least {sum(n for _, n in MINIMUMS)}", file=sys.stderr)
        return 2
    handlers = {"generate": cmd_generate, "reveal": cmd_reveal, "import": cmd_import}
    try:
        return handlers[args.command](args)
    except PwgenError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
