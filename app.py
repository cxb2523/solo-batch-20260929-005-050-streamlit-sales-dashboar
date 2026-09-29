"""Local credential management web app.

The key/hashing logic originally living in generate_keys.py (bcrypt hashed
passwords for the sales dashboard users) is served by this FastAPI app:

* ``GET  /``             -> server rendered credential panel (read-only badge)
* ``POST /keys/rotate``  -> read new passphrases from stdin, hash + persist
* ``POST /keys/verify``  -> verify a passphrase read from stdin

Credentials are persisted to ``credentials.json`` with ``version`` and
``algorithm`` fields.  The legacy ``hashed_pw.pkl`` file stays readable and is
migrated to JSON on the first write, with the original byte-for-byte restored
if the migration fails midway.

Run with::

    uvicorn app:app
"""

from __future__ import annotations

import json
import logging
import os
import pickle
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import anyio
import bcrypt
from filelock import FileLock
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_PATH = Path(os.environ.get("CREDENTIALS_FILE", BASE_DIR / "credentials.json"))
LEGACY_PICKLE_PATH = Path(os.environ.get("LEGACY_PICKLE", BASE_DIR / "hashed_pw.pkl"))
ENV_CREDENTIALS_VAR = os.environ.get("CREDENTIALS_ENV_VAR", "CREDENTIALS_JSON")
CONFIG_DIR = Path(os.environ.get("CREDENTIALS_CONFIG_DIR", Path.home() / ".config" / "sales-dashboard"))
WATCH_INTERVAL = float(os.environ.get("CREDENTIALS_WATCH_INTERVAL", "1.0"))
HOT_RELOAD_WINDOW = 5.0
BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))

CURRENT_VERSION = 1
SUPPORTED_ALGORITHMS = frozenset({"bcrypt"})
USERS = ("pparker", "rmiller")
FULL_NAMES = {"pparker": "Peter Parker", "rmiller": "Rebecca Miller"}

SHANGHAI_TZ = timezone(timedelta(hours=8))

logger = logging.getLogger("credentials")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


class CredentialError(Exception):
    """Raised when credential data is structurally invalid."""


@dataclass
class UserEntry:
    username: str
    full_name: str
    password_hash: str
    rotated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "full_name": self.full_name,
            "password_hash": self.password_hash,
            "rotated_at": self.rotated_at,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "UserEntry":
        if not isinstance(data, dict):
            raise CredentialError("user entry must be an object")
        username = data.get("username")
        if not isinstance(username, str) or not username:
            raise CredentialError("user entry requires a username")
        password_hash = data.get("password_hash")
        if not isinstance(password_hash, str) or not password_hash:
            raise CredentialError("user entry requires a password_hash")
        full_name = data.get("full_name", username)
        if not isinstance(full_name, str):
            raise CredentialError("full_name must be a string")
        rotated_at = data.get("rotated_at")
        if rotated_at is not None and not isinstance(rotated_at, str):
            raise CredentialError("rotated_at must be a string")
        return cls(username=username, full_name=full_name,
                   password_hash=password_hash, rotated_at=rotated_at)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_shanghai(iso_text: str | None) -> str:
    if not iso_text:
        return "—"
    try:
        moment = datetime.fromisoformat(iso_text)
    except ValueError:
        return iso_text
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(SHANGHAI_TZ).strftime("%Y-%m-%d %H:%M:%S") + " UTC+8"


def hash_passphrase(passphrase: str) -> str:
    if not isinstance(passphrase, str) or not passphrase:
        raise CredentialError("passphrase must be a non-empty string")
    if len(passphrase.encode("utf-8")) > 72:
        raise CredentialError("bcrypt passphrase must be at most 72 bytes")
    digest = bcrypt.hashpw(passphrase.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
    return digest.decode("utf-8")


def verify_passphrase(passphrase: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(passphrase.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def validate_credential_doc(doc: Any, minimum_version: int = CURRENT_VERSION) -> dict[str, Any]:
    """Validate source/algorithm/version fields. Raises CredentialError."""
    if not isinstance(doc, dict):
        raise CredentialError("credentials document must be an object")
    version = doc.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise CredentialError("version must be an integer")
    if version < minimum_version:
        raise CredentialError(
            f"illegal version downgrade: {version} < required {minimum_version}")
    algorithm = doc.get("algorithm")
    if not isinstance(algorithm, str) or algorithm not in SUPPORTED_ALGORITHMS:
        raise CredentialError(f"unsupported algorithm: {algorithm!r}")
    users = doc.get("users")
    if not isinstance(users, list) or not users:
        raise CredentialError("users must be a non-empty list")
    for entry in users:
        UserEntry.from_dict(entry)
    return doc


def doc_from_pickle(raw: list[str]) -> dict[str, Any]:
    if not isinstance(raw, list) or len(raw) != len(USERS):
        raise CredentialError("legacy pickle must contain one hash per user")
    users: list[dict[str, Any]] = []
    for username, password_hash in zip(USERS, raw):
        if not isinstance(password_hash, str) or not password_hash.startswith("$2"):
            raise CredentialError("legacy pickle entries must be bcrypt hashes")
        users.append({
            "username": username,
            "full_name": FULL_NAMES.get(username, username),
            "password_hash": password_hash,
            "rotated_at": None,
        })
    return {
        "version": CURRENT_VERSION,
        "algorithm": "bcrypt",
        "source_note": "migrated-from-pickle",
        "users": users,
    }


@dataclass
class CredentialStore:
    credentials_path: Path = CREDENTIALS_PATH
    legacy_pickle_path: Path = LEGACY_PICKLE_PATH
    env_var: str = ENV_CREDENTIALS_VAR
    config_dir: Path = CONFIG_DIR
    watch_interval: float = WATCH_INTERVAL

    users: list[UserEntry] = field(default_factory=list)
    version: int = 0
    algorithm: str = "bcrypt"
    source: str = "none"
    read_only: bool = False
    read_only_reason: str = ""
    rotated_at: str | None = None
    last_verified: str | None = None
    migration_pending: bool = False
    _signature: tuple = field(default_factory=tuple)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _stdin_lock: threading.Lock = field(default_factory=threading.Lock)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    # ------------------------------------------------------------------ load
    def start(self) -> None:
        self._load_initial()
        if self.source == "file" and self.watch_interval > 0:
            self._thread = threading.Thread(
                target=self._watch_loop, name="credentials-watcher", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _load_initial(self) -> None:
        try:
            doc, source = self._resolve_source()
            validate_credential_doc(doc)
            self._adopt_doc(doc, source)
            logger.info("credentials loaded from source=%s version=%s algorithm=%s",
                        source, self.version, self.algorithm)
        except CredentialError as exc:
            self._enter_read_only(f"startup validation failed: {exc}")
        except (OSError, ValueError, KeyError, pickle.PickleError) as exc:
            self._enter_read_only(f"startup source unreadable: {exc}")

    def _enter_read_only(self, reason: str) -> None:
        self.read_only = True
        self.read_only_reason = reason
        logger.warning("credential store switched to read-only: %s", reason)

    def _resolve_source(self) -> tuple[dict[str, Any], str]:
        # Precedence: file > environment variable > config directory > legacy pickle
        if self.credentials_path.exists():
            with self.credentials_path.open("r", encoding="utf-8") as handle:
                doc = json.load(handle)
            return doc, "file"
        env_value = os.environ.get(self.env_var)
        if env_value:
            doc = json.loads(env_value)
            return doc, "environment"
        config_path = self.config_dir / "credentials.json"
        if config_path.exists():
            with config_path.open("r", encoding="utf-8") as handle:
                doc = json.load(handle)
            return doc, "config-dir"
        if self.legacy_pickle_path.exists():
            with self.legacy_pickle_path.open("rb") as handle:
                raw = pickle.load(handle)
            doc = doc_from_pickle(raw)
            self.migration_pending = True
            return doc, "legacy-pickle"
        raise CredentialError("no credential source available")

    def _adopt_doc(self, doc: dict[str, Any], source: str) -> None:
        self.users = [UserEntry.from_dict(item) for item in doc["users"]]
        self.version = doc["version"]
        self.algorithm = doc["algorithm"]
        self.source = source
        timestamps = [item.rotated_at for item in self.users if item.rotated_at]
        self.rotated_at = max(timestamps) if timestamps else None
        self._signature = self._file_signature()
    # -------------------------------------------------------------- persistence
    def _file_signature(self) -> tuple:
        try:
            stat = self.credentials_path.stat()
            return (stat.st_mtime_ns, stat.st_size)
        except OSError:
            return (0, 0)

    def _atomic_write_json(self, doc: dict[str, Any]) -> None:
        """Write JSON via a same-directory temp file and os.replace."""
        target = self.credentials_path
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".credentials.", suffix=".tmp",
                                        dir=str(target.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(doc, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, target)
        except BaseException:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def _file_lock(self) -> FileLock:
        return FileLock(str(self.credentials_path) + ".lock")

    def _ensure_migrated(self) -> None:
        """First write migrates the legacy pickle to JSON; restore on failure."""
        if not self.migration_pending:
            return
        original_bytes: bytes | None = None
        pre_existed = self.credentials_path.exists()
        if pre_existed:
            original_bytes = self.credentials_path.read_bytes()
        doc = self._current_doc()
        try:
            self._atomic_write_json(doc)
        except BaseException:
            try:
                if pre_existed and original_bytes is not None:
                    self.credentials_path.write_bytes(original_bytes)
                else:
                    self.credentials_path.unlink(missing_ok=True)
            except OSError as restore_error:
                logger.error("migration rollback failed: %s", restore_error)
                raise
            raise
        self.migration_pending = False
        logger.info("legacy credentials migrated to %s", self.credentials_path)

    def _current_doc(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "users": [entry.to_dict() for entry in self.users],
        }

    # --------------------------------------------------------------- hot reload
    def _watch_loop(self) -> None:
        while not self._stop.wait(self.watch_interval):
            try:
                self._maybe_reload()
            except Exception as exc:  # watcher must never kill the process
                logger.exception("credential watcher error: %s", exc)

    def _maybe_reload(self) -> None:
        if self.source != "file":
            return
        signature = self._file_signature()
        if signature == self._signature or signature == (0, 0):
            return
        with self._lock:
            try:
                with self.credentials_path.open("r", encoding="utf-8") as handle:
                    doc = json.load(handle)
                validate_credential_doc(doc, minimum_version=self.version)
            except (OSError, ValueError, CredentialError) as exc:
                self._enter_read_only(f"hot reload validation failed: {exc}")
                self._signature = signature
                return
            self._adopt_doc(doc, "file")
        logger.info("credentials hot-reloaded (version=%s)", self.version)

    # --------------------------------------------------------------- mutations
    def ensure_watcher(self) -> None:
        if self._thread is None and self.watch_interval > 0 and self.source == "file":
            self._stop = threading.Event()
            self._thread = threading.Thread(
                target=self._watch_loop, name="credentials-watcher", daemon=True)
            self._thread.start()

    def require_writable(self) -> None:
        if self.read_only:
            raise ReadOnlyError(self.read_only_reason)

    def rotate(self, passphrases: dict[str, str]) -> dict[str, Any]:
        self.require_writable()
        missing = [name for name in USERS if name not in passphrases]
        if missing:
            raise CredentialError(f"missing passphrases for: {', '.join(missing)}")
        stamp = utc_now_iso()
        with self._lock, self._file_lock():
            self._ensure_migrated()
            disk_version = self.version
            if self.credentials_path.exists():
                try:
                    with self.credentials_path.open("r", encoding="utf-8") as handle:
                        disk_version = json.load(handle).get("version", self.version)
                except (OSError, ValueError):
                    disk_version = self.version
            next_users: list[UserEntry] = []
            for username in USERS:
                password_hash = hash_passphrase(passphrases[username])
                next_users.append(UserEntry(
                    username=username,
                    full_name=FULL_NAMES.get(username, username),
                    password_hash=password_hash,
                    rotated_at=stamp,
                ))
            next_version = max(self.version, disk_version, CURRENT_VERSION) + 1
            doc = {
                "version": next_version,
                "algorithm": "bcrypt",
                "users": [entry.to_dict() for entry in next_users],
            }
            self._atomic_write_json(doc)
            self.users = next_users
            self.version = next_version
            self.algorithm = "bcrypt"
            self.source = "file"
            self.rotated_at = stamp
            self._signature = self._file_signature()
            self.ensure_watcher()
        logger.info("credentials rotated (version=%s)", self.version)
        return self.snapshot()

    def verify(self, username: str, passphrase: str) -> bool:
        with self._lock:
            entry = next((item for item in self.users if item.username == username), None)
            if entry is None:
                return False
            ok = verify_passphrase(passphrase, entry.password_hash)
            self.last_verified = utc_now_iso()
        if ok:
            logger.info("verification succeeded for user=%s", username)
        else:
            logger.warning("verification failed for user=%s", username)
        return ok

    # ----------------------------------------------------------------- helpers
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "read_only": self.read_only,
                "read_only_reason": self.read_only_reason,
                "source": self.source,
                "version": self.version,
                "algorithm": self.algorithm,
                "migration_pending": self.migration_pending,
                "rotated_at": self.rotated_at,
                "rotated_at_local": to_shanghai(self.rotated_at),
                "last_verified": self.last_verified,
                "users": [
                    {
                        "username": entry.username,
                        "full_name": entry.full_name,
                        "password_hash": entry.password_hash[:7] + "…",
                        "rotated_at": to_shanghai(entry.rotated_at),
                    }
                    for entry in self.users
                ],
            }


class ReadOnlyError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
# --------------------------------------------------------------------- stdin
def _read_stdin_lines(count: int) -> list[str]:
    """Read exactly ``count`` lines from the real process stdin only.

    Passphrases never come from the environment, query string or request body.
    """
    lines: list[str] = []
    for _ in range(count):
        raw = sys.stdin.readline()
        if raw == "":
            break
        lines.append(raw.rstrip("\r\n"))
    return lines


def parse_rotation_input(lines: list[str]) -> dict[str, str]:
    """Map stdin lines to users. Two formats: ``username:pass`` xN or plain
    passphrases in the canonical user order."""
    pairs: dict[str, str] = {}
    if any(":" in line for line in lines):
        for line in lines:
            username, sep, passphrase = line.partition(":")
            if not sep or not username.strip() or not passphrase:
                raise CredentialError(f"invalid input line, expected 'username:pass'")
            pairs[username.strip()] = passphrase
    else:
        if len(lines) != len(USERS):
            raise CredentialError(
                f"expected {len(USERS)} passphrase lines, got {len(lines)}")
        pairs = dict(zip(USERS, lines))
    unknown = sorted(set(pairs) - set(USERS))
    if unknown:
        raise CredentialError(f"unknown users: {', '.join(unknown)}")
    return pairs


def parse_verify_input(line: str) -> tuple[str, str]:
    username, sep, passphrase = line.partition(":")
    if not sep or not username.strip() or not passphrase:
        raise CredentialError("expected a single 'username:pass' line on stdin")
    return username.strip(), passphrase


# ----------------------------------------------------------------------- app
PANEL_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>凭证管理面板</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; font-family: "Segoe UI", "Microsoft YaHei", sans-serif;
         background:#00172B; color:#EAF2F8; }
  main { max-width:860px; margin:0 auto; padding:32px 24px 64px; }
  h1 { font-size:24px; margin:0 0 4px; }
  .sub { color:#9DB2C3; margin-bottom:24px; }
  .badge { display:inline-block; padding:4px 12px; border-radius:999px;
           font-size:13px; font-weight:600; letter-spacing:.5px; }
  .badge.ro { background:#5A1D24; color:#FFB3BA; border:1px solid #8B2C36; }
  .badge.rw { background:#143D2B; color:#9BE8B8; border:1px solid #236B49; }
  .card { background:#0B2942; border:1px solid #16405F; border-radius:12px;
          padding:18px 20px; margin-top:18px; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #143550;
           font-size:14px; }
  th { color:#8FB0C5; font-weight:600; }
  code { background:#081F33; padding:2px 6px; border-radius:6px;
         font-family:Consolas, monospace; }
  dl { display:grid; grid-template-columns:160px 1fr; gap:8px 16px; margin:0; }
  dt { color:#8FB0C5; }
  .warn { background:#3A2410; border:1px solid #7A5022; color:#FFD9A8;
          padding:10px 14px; border-radius:8px; margin-top:12px; font-size:14px; }
  .muted { color:#7E97A8; font-size:12px; margin-top:20px; }
</style>
</head>
<body>
<main>
  <h1>🔐 凭证管理面板</h1>
  <div class="sub">sales dashboard · bcrypt credential store</div>
  <span id="mode-badge" class="badge __BADGE_CLASS__">__BADGE_TEXT__</span>
  <div id="ro-reason" class="warn" style="display:__REASON_DISPLAY__">__REASON__</div>

  <section class="card">
    <dl>
      <dt>凭证来源</dt><dd><code id="source">__SOURCE__</code></dd>
      <dt>版本</dt><dd><code id="version">__VERSION__</code></dd>
      <dt>哈希算法</dt><dd><code id="algorithm">__ALGORITHM__</code></dd>
      <dt>待迁移</dt><dd id="migration">__MIGRATION__</dd>
      <dt>最近轮换时间</dt><dd id="rotated-at">__ROTATED__</dd>
      <dt>最近校验时间</dt><dd id="verified-at">__VERIFIED__</dd>
    </dl>
  </section>

  <section class="card">
    <table>
      <thead><tr><th>用户名</th><th>姓名</th><th>口令哈希</th><th>轮换时间</th></tr></thead>
      <tbody id="users">__USER_ROWS__</tbody>
    </table>
  </section>

  <section class="card">
    <p style="margin-top:0">口令只能从服务进程 <code>stdin</code> 提供，不经过环境变量、URL 或请求体：</p>
    <pre style="overflow:auto"><code># 轮换（两行明文，或 username:pass 行）
printf 'secret-one\nsecret-two\n' | curl -X POST http://127.0.0.1:8000/keys/rotate
# 校验
printf 'pparker:secret-one\n' | curl -X POST http://127.0.0.1:8000/keys/verify</code></pre>
  </section>
  <p class="muted">页面每 3 秒轮询 /keys/state；文件来源在轮换后 5 秒内热加载，其它来源改动不触发重载。</p>
</main>
<script>
async function refresh() {
  try {
    const res = await fetch('/keys/state', {cache:'no-store'});
    const s = await res.json();
    const badge = document.getElementById('mode-badge');
    badge.textContent = s.read_only ? '只读 READ-ONLY' : '可读写 READ-WRITE';
    badge.className = 'badge ' + (s.read_only ? 'ro' : 'rw');
    const reason = document.getElementById('ro-reason');
    reason.style.display = s.read_only ? 'block' : 'none';
    reason.textContent = s.read_only_reason || '';
    document.getElementById('source').textContent = s.source;
    document.getElementById('version').textContent = String(s.version);
    document.getElementById('algorithm').textContent = s.algorithm;
    document.getElementById('migration').textContent = s.migration_pending ? '是（首次写盘迁移为 JSON）' : '否';
    document.getElementById('rotated-at').textContent = s.rotated_at_local;
    document.getElementById('verified-at').textContent = s.last_verified || '—';
    document.getElementById('users').innerHTML = s.users.map(u =>
      `<tr><td>${u.username}</td><td>${u.full_name}</td><td><code>${u.password_hash}</code></td><td>${u.rotated_at}</td></tr>`
    ).join('');
  } catch (err) { /* keep last rendered state */ }
}
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


def render_panel(snap: dict[str, Any]) -> str:
    rows = "".join(
        f"<tr><td>{u['username']}</td><td>{u['full_name']}</td>"
        f"<td><code>{u['password_hash']}</code></td><td>{u['rotated_at']}</td></tr>"
        for u in snap["users"]
    )
    replacements = {
        "__BADGE_CLASS__": "ro" if snap["read_only"] else "rw",
        "__BADGE_TEXT__": "只读 READ-ONLY" if snap["read_only"] else "可读写 READ-WRITE",
        "__REASON_DISPLAY__": "block" if snap["read_only"] else "none",
        "__REASON__": snap["read_only_reason"] or "",
        "__SOURCE__": snap["source"],
        "__VERSION__": str(snap["version"]),
        "__ALGORITHM__": snap["algorithm"],
        "__MIGRATION__": "是（首次写盘迁移为 JSON）" if snap["migration_pending"] else "否",
        "__ROTATED__": snap["rotated_at_local"],
        "__VERIFIED__": to_shanghai(snap["last_verified"]),
        "__USER_ROWS__": rows,
    }
    html = PANEL_TEMPLATE
    for key, value in replacements.items():
        html = html.replace(key, value)
    return html

def create_app(cred_store: CredentialStore | None = None) -> FastAPI:
    from contextlib import asynccontextmanager

    store = cred_store or get_store()

    @asynccontextmanager
    async def lifespan(api: FastAPI) -> Iterator[None]:
        yield
        store.stop()

    api = FastAPI(title="Credential Manager", docs_url="/docs",
                  redoc_url=None, lifespan=lifespan)

    @api.get("/", response_class=HTMLResponse)
    def panel() -> str:
        return render_panel(store.snapshot())

    @api.get("/keys/state")
    def state() -> dict[str, Any]:
        return store.snapshot()

    @api.post("/keys/rotate")
    async def rotate() -> JSONResponse:
        if store.read_only:
            return JSONResponse(
                status_code=409,
                content={"error": "read-only",
                         "reason": store.read_only_reason,
                         "state": store.snapshot()})
        lines = await anyio.to_thread.run_sync(
            lambda: _read_stdin_lines_locked(len(USERS), store))
        raw = list(lines)
        try:
            passphrases = parse_rotation_input(raw)
            snap = store.rotate(passphrases)
            return JSONResponse(status_code=200,
                                content={"status": "rotated", "state": snap})
        except ReadOnlyError as exc:
            return JSONResponse(status_code=409,
                                content={"error": "read-only", "reason": exc.reason,
                                         "state": store.snapshot()})
        except CredentialError as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})
        finally:
            for idx in range(len(raw)):
                raw[idx] = ""

    @api.post("/keys/verify")
    async def verify() -> JSONResponse:
        if store.read_only:
            return JSONResponse(
                status_code=409,
                content={"error": "read-only",
                         "reason": store.read_only_reason,
                         "state": store.snapshot()})
        lines = await anyio.to_thread.run_sync(
            lambda: _read_stdin_lines_locked(1, store))
        raw = list(lines)
        try:
            username, passphrase = parse_verify_input(raw[0] if raw else "")
            ok = store.verify(username, passphrase)
            return JSONResponse(
                status_code=200 if ok else 401,
                content={"valid": ok, "username": username,
                         "checked_at": store.last_verified})
        except CredentialError as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})
        finally:
            for idx in range(len(raw)):
                raw[idx] = ""

    return api


def _read_stdin_lines_locked(count: int, store: CredentialStore) -> list[str]:
    with store._stdin_lock:
        return _read_stdin_lines(count)


_STORE: CredentialStore | None = None
_STORE_GUARD = threading.Lock()


def get_store() -> CredentialStore:
    global _STORE
    with _STORE_GUARD:
        if _STORE is None:
            _STORE = CredentialStore()
            _STORE.start()
        return _STORE


def reset_store(new_store: CredentialStore | None = None) -> None:
    """Test hook: replace the process-wide store."""
    global _STORE
    with _STORE_GUARD:
        if _STORE is not None:
            _STORE.stop()
        _STORE = new_store


app = create_app(get_store())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)