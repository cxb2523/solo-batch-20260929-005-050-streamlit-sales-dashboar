import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import bcrypt
import pytest
from fastapi.testclient import TestClient

import app as app_module
from app import (
    CredentialStore,
    ReadOnlyError,
    create_app,
    read_secret_from_stdin,
    wipe_secret,
)


PICKLE_USERS = ("pparker", "rmiller")


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    legacy = Path(__file__).with_name("hashed_pw.pkl")
    (tmp_path / "hashed_pw.pkl").write_bytes(legacy.read_bytes())
    return tmp_path


def make_store(tmp_path: Path, reader=None, env=None) -> CredentialStore:
    return CredentialStore(
        credentials_file=tmp_path / "credentials.json",
        env_credentials=env,
        config_dir_file=tmp_path / ".streamlit" / "credentials.json",
        legacy_pickle=tmp_path / "hashed_pw.pkl",
        secret_reader=reader or (lambda prompt: bytearray(b"hunter2")),
    )


def write_json_credentials(path: Path, **over) -> None:
    hashed = bcrypt.hashpw(b"orig-pass", bcrypt.gensalt()).decode("ascii")
    payload = {
        "version": 1,
        "algorithm": "bcrypt",
        "revision": 1,
        "rotated_at": "2026-01-01T00:00:00Z",
        "credentials": {"alice": {"hash": hashed}},
    }
    payload.update(over)
    path.write_text(json.dumps(payload), encoding="utf-8")


# --- legacy pickle reads / JSON migration ---------------------------------

def test_legacy_pickle_still_readable(workdir: Path) -> None:
    store = make_store(workdir)
    assert store.source == "legacy-pickle"
    assert store.read_only is False
    assert set(store.credentials) == set(PICKLE_USERS)


def test_first_write_migrates_pickle_to_json(workdir: Path) -> None:
    original_bytes = (workdir / "hashed_pw.pkl").read_bytes()
    store = make_store(workdir)
    result = store.rotate()
    assert result["migrated"] is True
    creds_file = workdir / "credentials.json"
    assert creds_file.exists()
    assert not (workdir / "hashed_pw.pkl").exists()
    on_disk = json.loads(creds_file.read_text(encoding="utf-8"))
    assert on_disk["version"] == 1
    assert on_disk["algorithm"] == "bcrypt"
    assert set(on_disk["credentials"]) == set(PICKLE_USERS)
    assert bcrypt.checkpw(b"hunter2", on_disk["credentials"]["pparker"]["hash"].encode())

    # Fresh store loads the JSON file, not env/config-dir.
    reloaded = CredentialStore(
        credentials_file=creds_file,
        env_credentials=None,
        config_dir_file=workdir / ".streamlit" / "credentials.json",
        legacy_pickle=workdir / "hashed_pw.pkl",
    )
    assert reloaded.source == "file"
    assert reloaded.version == 1

    # backup temp files are cleaned up
    leftovers = [p for p in workdir.iterdir() if p.suffix in (".bak", ".tmp")]
    assert leftovers == []

    # sanity: original pickle bytes were a valid list before retirement
    assert original_bytes[:2] == b"\x80\x04"


def test_migration_failure_restores_original_pickle(workdir: Path, monkeypatch) -> None:
    original_bytes = (workdir / "hashed_pw.pkl").read_bytes()
    store = make_store(workdir)
    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(src, dst):
        # Fail when promoting the JSON file over credentials.json.
        calls["n"] += 1
        if Path(dst).name == "credentials.json":
            raise OSError("simulated disk failure")
        return real_replace(src, dst)

    monkeypatch.setattr(app_module.os, "replace", flaky_replace)
    with pytest.raises(OSError):
        store.rotate()

    assert (workdir / "hashed_pw.pkl").read_bytes() == original_bytes
    assert not (workdir / "credentials.json").exists()
    leftovers = [
        p
        for p in workdir.iterdir()
        if p.name.endswith((".tmp", ".bak", ".migrating"))
    ]
    assert leftovers == []
    # service still serves the restored legacy file
    assert store.source == "legacy-pickle"
    assert store.read_only is False


# --- invalid version / algorithm => read-only + 409 -----------------------

def test_newer_version_forces_readonly(workdir: Path) -> None:
    write_json_credentials(workdir / "credentials.json", version=99)
    store = make_store(workdir)
    assert store.read_only is True
    assert "version" in (store.error or "")
    with pytest.raises(ReadOnlyError):
        store.rotate()


def test_unsupported_algorithm_forces_readonly(workdir: Path) -> None:
    write_json_credentials(workdir / "credentials.json", algorithm="md5")
    store = make_store(workdir)
    assert store.read_only is True
    with pytest.raises(ReadOnlyError):
        store.rotate()


def test_rotate_endpoint_returns_409_when_readonly(workdir: Path) -> None:
    write_json_credentials(workdir / "credentials.json", version=42)
    store = make_store(workdir)
    client = TestClient(create_app(store))
    response = client.post("/keys/rotate", json={})
    assert response.status_code == 409
    body = response.json()
    assert body["status"] == "read-only"
    assert body["state"]["read_only"] is True


def test_verify_endpoint_409_without_credentials(workdir: Path) -> None:
    (workdir / "hashed_pw.pkl").unlink()
    (workdir / "credentials.json").write_text("{not json", encoding="utf-8")
    store = make_store(workdir)
    client = TestClient(create_app(store))
    response = client.post("/keys/verify", json={"username": "alice"})
    assert response.status_code == 409


# --- concurrent rotation --------------------------------------------------

def test_concurrent_rotations_serialised_in_process(workdir: Path) -> None:
    store = make_store(workdir)
    gate = threading.Event()
    entered = threading.Event()

    def gated_reader(prompt: str) -> bytearray:
        entered.set()
        gate.wait(timeout=5)
        return bytearray(b"new-secret")

    store.read_secret = gated_reader
    errors: list[Exception] = []

    def worker() -> None:
        try:
            store.rotate(["pparker"])
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    first = threading.Thread(target=worker)
    first.start()
    assert entered.wait(timeout=2)
    # Second rotation must block behind the file lock / RLock.
    second = threading.Thread(target=worker)
    second.start()
    time.sleep(0.5)
    assert first.is_alive()
    assert second.is_alive()
    gate.set()
    first.join(timeout=10)
    second.join(timeout=10)
    assert errors == []
    assert store.revision == 2
    on_disk = json.loads((workdir / "credentials.json").read_text(encoding="utf-8"))
    assert on_disk["revision"] == 2
    assert bcrypt.checkpw(
        b"new-secret", on_disk["credentials"]["pparker"]["hash"].encode()
    )


def test_concurrent_rotation_serialised_across_processes(workdir: Path) -> None:
    creds = workdir / "credentials.json"
    lock = workdir / "credentials.json.lock"
    write_json_credentials(creds, revision=1)
    helper = workdir / "rotate_helper.py"
    helper.write_text(
        "\n".join(
            (
                "import sys, time",
                "sys.path.insert(0, %r)" % str(Path(__file__).parent),
                "from pathlib import Path",
                "from app import CredentialStore, _file_lock",
                "lock = Path(%r)" % str(lock),
                "got = False",
                "with _file_lock(lock):",
                "    got = True",
                "    time.sleep(1.5)",
                "print('held' if got else 'missed')",
            )
        ),
        encoding="utf-8",
    )
    env = dict(os.environ)
    p1 = subprocess.Popen(
        [sys.executable, str(helper)],
        cwd=workdir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.4)
    start = time.monotonic()
    p2 = subprocess.run(
        [sys.executable, str(helper)],
        cwd=workdir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    waited = time.monotonic() - start
    out1 = p1.communicate(timeout=10)[0].decode().strip()
    assert out1 == "held"
    assert p2.returncode == 0
    assert p2.stdout.strip() == "held"
    assert waited >= 1.0


# --- source priority / hot reload -----------------------------------------

def test_file_source_takes_priority(workdir: Path) -> None:
    (workdir / "hashed_pw.pkl").unlink()
    write_json_credentials(workdir / "credentials.json")
    env_payload = json.dumps(
        {
            "version": 1,
            "algorithm": "bcrypt",
            "credentials": {"envuser": {"hash": "x"}},
        }
    )
    store = make_store(workdir, env=env_payload)
    assert store.source == "file"
    assert "alice" in store.credentials


def test_env_used_without_file(workdir: Path) -> None:
    (workdir / "hashed_pw.pkl").unlink()
    env_payload = json.dumps(
        {
            "version": 1,
            "algorithm": "bcrypt",
            "credentials": {"envuser": {"hash": "x"}},
        }
    )
    store = make_store(workdir, env=env_payload)
    assert store.source == "env"


def test_file_change_hot_reloaded_within_5s(workdir: Path) -> None:
    creds = workdir / "credentials.json"
    write_json_credentials(creds, revision=1)
    store = make_store(workdir)
    assert store.revision == 1
    write_json_credentials(creds, revision=7)
    deadline = time.monotonic() + 5.0
    reloaded = False
    while time.monotonic() < deadline:
        if store.reload_if_file_changed():
            reloaded = True
            break
        time.sleep(0.1)
    assert reloaded is True
    assert store.revision == 7


def test_watcher_picks_up_late_change_within_budget(workdir: Path) -> None:
    creds = workdir / "credentials.json"
    write_json_credentials(creds, revision=1)
    store = make_store(workdir)
    store.start_watcher()
    try:
        # A change arriving well after startup (not just within 5 s of boot).
        time.sleep(5.5)
        write_json_credentials(creds, revision=4)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and store.revision != 4:
            time.sleep(0.1)
        assert store.revision == 4
    finally:
        store.stop_watcher()


def test_non_file_source_change_never_reloads(workdir: Path) -> None:
    (workdir / "hashed_pw.pkl").unlink()
    env_payload = json.dumps(
        {
            "version": 1,
            "algorithm": "bcrypt",
            "revision": 1,
            "credentials": {"envuser": {"hash": "x"}},
        }
    )
    store = make_store(workdir, env=env_payload)
    assert store.source == "env"
    # env var content cannot change after process start; reload must no-op.
    assert store.reload_if_file_changed() is False


# --- passphrase handling --------------------------------------------------

def test_passphrase_read_from_stdin_then_wiped(monkeypatch, capsys) -> None:
    import io as io_module

    class FakeStdin:
        def __init__(self, raw: bytes) -> None:
            self.buffer = io_module.BytesIO(raw)

        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("sys.stdin", FakeStdin(b"s3cret-line\n"))
    secret = read_secret_from_stdin("prompt: ")
    assert bytes(secret) == b"s3cret-line"
    wipe_secret(secret)
    assert bytes(secret) == b"\x00" * len("s3cret-line")
    captured = capsys.readouterr()
    assert "s3cret-line" not in captured.out


def test_verify_checks_passphrase(workdir: Path) -> None:
    creds = workdir / "credentials.json"
    write_json_credentials(creds)
    answers = iter([bytearray(b"orig-pass"), bytearray(b"wrong")])
    store = make_store(workdir, reader=lambda prompt: next(answers))
    assert store.verify("alice")[0] is True
    ok, reason = store.verify("alice")
    assert ok is False
    assert reason == "passphrase mismatch"


def test_panel_renders(workdir: Path) -> None:
    write_json_credentials(workdir / "credentials.json")
    client = TestClient(create_app(make_store(workdir)))
    response = client.get("/")
    assert response.status_code == 200
    assert "Credential Panel" in response.text
