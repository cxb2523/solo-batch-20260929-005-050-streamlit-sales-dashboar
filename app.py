"""Local credential management web app.

Key material used to live in ``generate_keys.py`` / ``hashed_pw.pkl``.
This module turns that into a small ASGI service (``uvicorn app:app``):

* ``GET  /``            credential panel
* ``POST /keys/rotate`` rotate one or all credentials
* ``POST /keys/verify`` verify a credential
* ``GET  /keys/state``  machine readable status

Hard rules (fixed trade-offs):

1. The legacy pickle stays readable; the first write migrates it to
   ``credentials.json``. If anything fails mid-migration the original
   file is byte-for-byte restored.
2. Sources are, in priority order: credentials file, env var, config dir.
   A file change is hot-reloaded within 5 s of a rotation; env/config-dir
   changes never trigger a reload.
3. Passphrases are only read from stdin and wiped immediately afterwards;
   they are never put in env vars or logged.
"""

from __future__ import annotations

import getpass
import json
import os
import pickle
import sys
import threading
import tempfile
import time
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import bcrypt
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel


BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = Path(os.environ.get("CREDENTIALS_FILE", BASE_DIR / "credentials.json"))
ENV_CREDENTIALS = os.environ.get("CREDENTIALS_JSON")
CONFIG_DIR = Path(os.environ.get("CREDENTIALS_CONFIG_DIR", BASE_DIR / ".streamlit"))
CONFIG_DIR_FILE = CONFIG_DIR / "credentials.json"
LEGACY_PICKLE = Path(os.environ.get("LEGACY_PICKLE", BASE_DIR / "hashed_pw.pkl"))

SUPPORTED_ALGORITHMS = frozenset({"bcrypt"})
SCHEMA_VERSION = 1
RELOAD_POLL_SECONDS = 1.0
RELOAD_DEBOUNCE_SECONDS = 0.2
# Contract: a file change must become visible within this many seconds.
# The 1 s poll (+ debounce) keeps us comfortably inside the budget; the
# watcher itself runs for the whole process lifetime.
RELOAD_BUDGET_SECONDS = 5.0


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def wipe_secret(secret: bytearray | None) -> None:
    """Best effort overwrite of a passphrase held in memory."""
    if secret is not None:
        for i in range(len(secret)):
            secret[i] = 0


class CredentialError(Exception):
    """Raised when a credential payload fails validation."""


class ReadOnlyError(CredentialError):
    """Raised when a mutating action is attempted in read-only mode."""


class _SafeUnpickler(pickle.Unpickler):
    """Unpickler that refuses to resolve any classes/functions."""

    def find_class(self, module: str, name: str) -> Any:  # pragma: no cover
        raise pickle.UnpicklingError(f"refusing to unpickle {module}.{name}")


@contextmanager
def _file_lock(lock_path: Path) -> Iterable[None]:
    """Cross-process advisory lock backed by a sibling ``.lock`` file."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def read_secret_from_stdin(prompt: str) -> bytearray:
    """Read one passphrase from stdin only.

    TTY: echo disabled, prompt goes to stderr (never stdout/logs).
    Non-TTY: a single line is consumed from stdin.
    """
    if sys.stdin is not None and sys.stdin.isatty():
        value = getpass.getpass(prompt=prompt, stream=sys.stderr)
        secret = bytearray(value, encoding="utf-8", errors="replace")
    else:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = sys.stdin.buffer.readline()
        if line.endswith(b"\n"):
            line = line[:-1]
        if line.endswith(b"\r"):
            line = line[:-1]
        secret = bytearray(line)
    return secret


SecretReader = Callable[[str], bytearray]


class CredentialStore:
    """Credential state with file-first sources and safe migration."""

    def __init__(
        self,
        credentials_file: Path | None = None,
        env_credentials: str | None | object = ...,
        config_dir_file: Path | None = None,
        legacy_pickle: Path | None = None,
        secret_reader: SecretReader = read_secret_from_stdin,
    ) -> None:
        self.credentials_file = credentials_file or CREDENTIALS_FILE
        self.env_credentials = (
            ENV_CREDENTIALS if env_credentials is ... else env_credentials
        )
        self.config_dir_file = config_dir_file or CONFIG_DIR_FILE
        self.legacy_pickle = legacy_pickle or LEGACY_PICKLE
        self.read_secret = secret_reader
        self.lock_path = self.credentials_file.with_suffix(
            self.credentials_file.suffix + ".lock"
        )
        self._lock = threading.RLock()
        self.credentials: dict[str, dict[str, str]] = {}
        self.version = 0
        self.algorithm = "bcrypt"
        self.revision = 0
        self.rotated_at: str | None = None
        self.source: str = "none"
        self.read_only = False
        self.error: str | None = None
        self._watch_stop = threading.Event()
        self._watch_thread: threading.Thread | None = None
        self._watched_mtime: float | None = None
        self.load()

    # ----- loading / validation --------------------------------------

    def _parse_json_payload(self, payload: Any, source: str) -> None:
        if not isinstance(payload, dict):
            raise CredentialError(f"{source}: payload must be a JSON object")
        version = payload.get("version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise CredentialError(f"{source}: missing integer 'version'")
        if version > SCHEMA_VERSION:
            raise CredentialError(
                f"{source}: credential version {version} is newer than the "
                f"supported version {SCHEMA_VERSION}; refusing to downgrade"
            )
        if version < 1:
            raise CredentialError(f"{source}: invalid 'version' {version}")
        algorithm = payload.get("algorithm")
        if algorithm not in SUPPORTED_ALGORITHMS:
            supported = ", ".join(sorted(SUPPORTED_ALGORITHMS))
            raise CredentialError(
                f"{source}: unsupported algorithm {algorithm!r} "
                f"(supported: {supported})"
            )
        credentials = payload.get("credentials")
        if not isinstance(credentials, dict) or not credentials:
            raise CredentialError(f"{source}: 'credentials' must be a non-empty object")
        clean: dict[str, dict[str, str]] = {}
        for username, entry in credentials.items():
            if not isinstance(username, str) or not isinstance(entry, dict):
                raise CredentialError(f"{source}: malformed credential entry")
            secret_hash = entry.get("hash")
            if not isinstance(secret_hash, str) or not secret_hash:
                raise CredentialError(f"{source}: credential for {username!r} lacks 'hash'")
            clean[username] = {"hash": secret_hash}
        self.credentials = clean
        self.version = version
        self.algorithm = algorithm
        self.revision = payload.get("revision") if isinstance(
            payload.get("revision"), int
        ) and not isinstance(payload.get("revision"), bool) else 0
        rotated_at = payload.get("rotated_at")
        self.rotated_at = rotated_at if isinstance(rotated_at, str) else None
        self.source = source

    def _read_legacy_pickle(self) -> bool:
        if not self.legacy_pickle.exists():
            return False
        with self.legacy_pickle.open("rb") as handle:
            hashes = _SafeUnpickler(handle).load()
        if not isinstance(hashes, (list, tuple)) or not hashes:
            raise CredentialError("legacy pickle: expected a non-empty list of hashes")
        names = ("pparker", "rmiller")
        clean: dict[str, dict[str, str]] = {}
        for index, secret_hash in enumerate(hashes):
            if not isinstance(secret_hash, str) or not secret_hash:
                raise CredentialError("legacy pickle: malformed hash entry")
            username = names[index] if index < len(names) else f"user{index + 1}"
            clean[username] = {"hash": secret_hash}
        self.credentials = clean
        self.version = 0
        self.algorithm = "bcrypt"
        self.revision = 0
        self.rotated_at = None
        self.source = "legacy-pickle"
        return True

    def _load_locked(self) -> None:
        self.error = None
        self.read_only = False
        # Priority 1: credentials file (JSON preferred, legacy pickle accepted).
        if self.credentials_file.exists():
            try:
                payload = json.loads(self.credentials_file.read_text(encoding="utf-8"))
                self._parse_json_payload(payload, "file")
                self._watched_mtime = self.credentials_file.stat().st_mtime
                return
            except (OSError, json.JSONDecodeError, CredentialError) as exc:
                self._enter_read_only(str(exc))
                return
        # Legacy pickle still readable until the first write migrates it.
        try:
            if self._read_legacy_pickle():
                self._watched_mtime = self.legacy_pickle.stat().st_mtime
                return
        except (OSError, pickle.UnpicklingError, CredentialError) as exc:
            self._enter_read_only(str(exc))
            return
        # Priority 2: environment variable.
        if self.env_credentials:
            try:
                self._parse_json_payload(json.loads(self.env_credentials), "env")
                return
            except (json.JSONDecodeError, CredentialError) as exc:
                self._enter_read_only(str(exc))
                return
        # Priority 3: config directory.
        if self.config_dir_file.exists():
            try:
                payload = json.loads(self.config_dir_file.read_text(encoding="utf-8"))
                self._parse_json_payload(payload, "config-dir")
                return
            except (OSError, json.JSONDecodeError, CredentialError) as exc:
                self._enter_read_only(str(exc))
                return
        self.credentials = {}
        self.source = "none"
        self.error = "no credential source found"

    def load(self) -> None:
        with self._lock:
            self._load_locked()

    def _enter_read_only(self, reason: str) -> None:
        self.read_only = True
        self.error = reason

    # ----- state -----------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "read_only": self.read_only,
                "source": self.source,
                "version": self.version,
                "algorithm": self.algorithm,
                "revision": self.revision,
                "rotated_at": self.rotated_at,
                "error": self.error,
                "users": list(self.credentials.keys()),
            }

    # ----- atomic writes / migration ---------------------------------

    def _atomic_write_json(self, path: Path, payload: dict[str, Any]) -> None:
        """Write via a temp file in the same directory, then os.replace."""
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
        except BaseException:
            with suppress(OSError):
                tmp_path.unlink()
            raise

    def _backup_legacy(self) -> tuple[Path, bytes]:
        fd, backup_name = tempfile.mkstemp(
            prefix=self.legacy_pickle.name + ".",
            suffix=".bak",
            dir=str(self.legacy_pickle.parent),
        )
        backup_path = Path(backup_name)
        raw = self.legacy_pickle.read_bytes()
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            with suppress(OSError):
                backup_path.unlink()
            raise
        return backup_path, raw

    def rotate_locked(
        self, usernames: list[str] | None = None
    ) -> dict[str, Any]:
        """Rotate credentials. Callers may already hold ``self._lock``."""
        if self.read_only:
            raise ReadOnlyError(self.error or "store is read-only")
        with _file_lock(self.lock_path):
            # Re-read under the cross-process lock so serialised rotations
            # never build on stale state.
            self._load_locked()
            if self.read_only:
                raise ReadOnlyError(self.error or "store is read-only")
            migrating = self.source == "legacy-pickle"
            backup_path: Path | None = None
            backup_raw = b""
            if migrating:
                backup_path, backup_raw = self._backup_legacy()

            targets = usernames or list(self.credentials.keys()) or ["admin"]
            unknown = [name for name in targets if name not in self.credentials]
            if unknown and self.credentials:
                raise CredentialError(
                    f"unknown username(s): {', '.join(sorted(unknown))}"
                )

            new_hashes: dict[str, str] = {}
            secrets: list[bytearray] = []
            try:
                for username in targets:
                    prompt = (
                        f"new passphrase for {username} "
                        f"(stdin only, not logged): "
                    )
                    secret = self.read_secret(prompt)
                    secrets.append(secret)
                    new_hashes[username] = bcrypt.hashpw(
                        bytes(secret), bcrypt.gensalt()
                    ).decode("ascii")
            finally:
                for secret in secrets:
                    wipe_secret(secret)

            merged = dict(self.credentials)
            for username, secret_hash in new_hashes.items():
                merged[username] = {"hash": secret_hash}
            now = _utcnow_iso()
            payload = {
                "version": SCHEMA_VERSION,
                "algorithm": "bcrypt",
                "revision": self.revision + 1,
                "rotated_at": now,
                "credentials": merged,
            }

            tmp_credentials = self.credentials_file.with_suffix(".json.migrating")
            try:
                # First land the JSON payload, then retire the pickle;
                # any failure restores the original file byte-for-byte.
                if migrating:
                    self._atomic_write_json(tmp_credentials, payload)
                    os.replace(tmp_credentials, self.credentials_file)
                    self.legacy_pickle.unlink()
                else:
                    self._atomic_write_json(self.credentials_file, payload)
            except BaseException:
                with suppress(OSError):
                    tmp_credentials.unlink()
                if migrating and backup_path is not None:
                    with suppress(OSError):
                        if self.credentials_file.exists():
                            self.credentials_file.unlink()
                    with open(self.legacy_pickle, "wb") as handle:
                        handle.write(backup_raw)
                        handle.flush()
                        os.fsync(handle.fileno())
                    self._load_locked()
                with suppress(OSError):
                    if backup_path is not None:
                        backup_path.unlink()
                raise
            else:
                with suppress(OSError):
                    if backup_path is not None:
                        backup_path.unlink()

            self.credentials = merged
            self.version = SCHEMA_VERSION
            self.algorithm = "bcrypt"
            self.revision = payload["revision"]
            self.rotated_at = now
            self.source = "file"
            self._watched_mtime = self.credentials_file.stat().st_mtime
            return {
                "rotated": targets,
                "revision": self.revision,
                "rotated_at": self.rotated_at,
                "source": self.source,
                "version": self.version,
                "algorithm": self.algorithm,
                "migrated": migrating,
            }

    def rotate(self, usernames: list[str] | None = None) -> dict[str, Any]:
        with self._lock:
            return self.rotate_locked(usernames)

    # ----- verification ----------------------------------------------

    def verify(self, username: str) -> tuple[bool, str | None]:
        with self._lock:
            entry = self.credentials.get(username)
            if entry is None:
                return False, "unknown username"
            secret = self.read_secret(
                f"passphrase for {username} (stdin only, not logged): "
            )
            try:
                ok = bcrypt.checkpw(bytes(secret), entry["hash"].encode("ascii"))
            except ValueError:
                return False, "malformed stored hash"
            finally:
                wipe_secret(secret)
            return ok, (None if ok else "passphrase mismatch")

    # ----- hot reload (file source only, within 5 s) -----------------

    def reload_if_file_changed(self) -> bool:
        """Reload only when the active credentials file changed on disk.

        Env/config-dir edits never trigger a reload by design.
        """
        with self._lock:
            if self.source == "file":
                path = self.credentials_file
            elif self.source == "legacy-pickle":
                path = self.legacy_pickle
            else:
                return False
            if not path.exists():
                return False
            mtime = path.stat().st_mtime
            if self._watched_mtime is not None and mtime <= self._watched_mtime:
                return False
            time.sleep(RELOAD_DEBOUNCE_SECONDS)
            mtime = path.stat().st_mtime
            if self._watched_mtime is not None and mtime <= self._watched_mtime:
                return False
            self._load_locked()
            return True

    def _watch_loop(self) -> None:
        while not self._watch_stop.wait(RELOAD_POLL_SECONDS):
            try:
                self.reload_if_file_changed()
            except Exception:
                pass

    def start_watcher(self) -> None:
        if self._watch_thread is not None:
            return
        self._watch_stop.clear()
        thread = threading.Thread(target=self._watch_loop, daemon=True)
        thread.start()
        self._watch_thread = thread

    def stop_watcher(self) -> None:
        self._watch_stop.set()
        thread = self._watch_thread
        if thread is not None:
            thread.join(timeout=2)
        self._watch_thread = None


class RotateRequest(BaseModel):
    usernames: list[str] | None = None


class VerifyRequest(BaseModel):
    username: str


PANEL_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Credential Panel</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 760px; }
  h1 { margin-bottom: .25rem; }
  .badge { display: inline-block; padding: .2rem .6rem; border-radius: 999px;
           font-size: .8rem; font-weight: 600; margin-left: .5rem; vertical-align: middle; }
  .badge.ok { background: #1b873f; color: #fff; }
  .badge.ro { background: #b00020; color: #fff; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { text-align: left; padding: .45rem .7rem; border-bottom: 1px solid #8884; }
  button { padding: .5rem 1rem; border-radius: .5rem; border: 0; cursor: pointer;
           background: #0066d6; color: #fff; font-size: .95rem; margin-right: .5rem; }
  button.secondary { background: #555; }
  #result { white-space: pre-wrap; background: #8882; padding: .8rem;
            border-radius: .5rem; min-height: 1.5rem; }
  .muted { color: #888; font-size: .85rem; }
</style>
</head>
<body>
<h1>Credential Panel
  <span id="mode" class="badge">...</span>
</h1>
<p class="muted">Passphrases are read from the <b>server process stdin</b>; they are
never sent in the request, put in env vars, or logged.</p>
<table>
  <tr><th>Active source</th><td id="source"></td></tr>
  <tr><th>Version / algorithm</th><td id="version"></td></tr>
  <tr><th>Revision</th><td id="revision"></td></tr>
  <tr><th>Last rotation</th><td id="rotated_at"></td></tr>
  <tr><th>Users</th><td id="users"></td></tr>
  <tr><th>Validation</th><td id="error"></td></tr>
</table>
<p>
  <button onclick="act('/keys/rotate')">Rotate all keys</button>
  <button class="secondary" onclick="act('/keys/state')">Refresh</button>
</p>
<div id="result"></div>
<script>
async function refresh() {
  const r = await fetch('/keys/state');
  const s = await r.json();
  const badge = document.getElementById('mode');
  badge.textContent = s.read_only ? 'READ-ONLY' : 'READ-WRITE';
  badge.className = 'badge ' + (s.read_only ? 'ro' : 'ok');
  document.getElementById('source').textContent = s.source;
  document.getElementById('version').textContent = 'v' + s.version + ' / ' + s.algorithm;
  document.getElementById('revision').textContent = s.revision;
  document.getElementById('rotated_at').textContent = s.rotated_at || '(never)';
  document.getElementById('users').textContent = s.users.join(', ') || '(none)';
  document.getElementById('error').textContent = s.error || 'OK';
}
async function act(url) {
  const out = document.getElementById('result');
  out.textContent = 'working ... enter the passphrase on the server stdin if prompted';
  try {
    const r = await fetch(url, {method: 'POST'});
    const body = await r.json();
    out.textContent = 'HTTP ' + r.status + '\\n' + JSON.stringify(body, null, 2);
  } catch (e) {
    out.textContent = String(e);
  }
  refresh();
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


def create_app(store: CredentialStore | None = None) -> FastAPI:
    from contextlib import asynccontextmanager

    resolved = store or CredentialStore()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Hot reload window: file changes after startup (including rotations)
        # are picked up within 5 seconds; other sources never reload.
        resolved.start_watcher()
        try:
            yield
        finally:
            resolved.stop_watcher()

    app = FastAPI(title="Local Credential Service", lifespan=lifespan)
    app.state.store = resolved

    @app.get("/", response_class=HTMLResponse)
    async def panel() -> str:
        return PANEL_HTML

    @app.get("/keys/state")
    async def state() -> dict[str, Any]:
        return app.state.store.snapshot()

    @app.post("/keys/rotate")
    async def rotate(request: RotateRequest) -> JSONResponse:
        try:
            result = app.state.store.rotate(request.usernames)
        except ReadOnlyError as exc:
            return JSONResponse(
                status_code=409,
                content={
                    "status": "read-only",
                    "error": str(exc),
                    "state": app.state.store.snapshot(),
                },
            )
        except CredentialError as exc:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "error": str(exc)},
            )
        return JSONResponse(content={"status": "rotated", "result": result})

    @app.post("/keys/verify")
    async def verify(request: VerifyRequest) -> JSONResponse:
        store: CredentialStore = app.state.store
        if store.read_only and not store.credentials:
            return JSONResponse(
                status_code=409,
                content={
                    "status": "read-only",
                    "error": store.error or "credentials unavailable",
                    "state": store.snapshot(),
                },
            )
        ok, reason = store.verify(request.username)
        return JSONResponse(
            status_code=200 if ok else 401,
            content={"status": "ok" if ok else "failed", "reason": reason},
        )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
