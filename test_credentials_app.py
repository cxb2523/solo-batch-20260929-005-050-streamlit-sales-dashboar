"""Acceptance tests for the credential web app.

Covers: concurrent rotation serialisation, migration rollback, illegal
version downgrade, source precedence, hot reload, stdin-only passphrases,
read-only 409 responses and the rendered panel badge.
"""

from __future__ import annotations

import io
import json
import os
import pickle
import threading
import time

import pytest
from fastapi.testclient import TestClient

import app as app_module
from app import CredentialStore, doc_from_pickle


@pytest.fixture(autouse=True)
def fast_bcrypt(monkeypatch):
    monkeypatch.setattr(app_module, "BCRYPT_ROUNDS", 4)


@pytest.fixture
def paths(tmp_path):
    return {
        "cred": tmp_path / "credentials.json",
        "pickle": tmp_path / "hashed_pw.pkl",
        "config_dir": tmp_path / "config",
        "env_var": "CREDENTIALS_JSON_TEST_" + tmp_path.name.upper(),
    }


def make_pickle(path, hashes=("$2b$12$" + "a" * 53, "$2b$12$" + "b" * 53)):
    path.write_bytes(pickle.dumps(list(hashes)))


def make_store(paths, watch_interval=0.0, env_doc=None, monkeypatch=None):
    if env_doc is not None:
        os.environ[paths["env_var"]] = json.dumps(env_doc)
    elif monkeypatch is not None:
        monkeypatch.delenv(paths["env_var"], raising=False)
    store = CredentialStore(
        credentials_path=paths["cred"],
        legacy_pickle_path=paths["pickle"],
        env_var=paths["env_var"],
        config_dir=paths["config_dir"],
        watch_interval=watch_interval,
    )
    store.start()
    return store


@pytest.fixture
def client_factory():
    created = []

    def _factory(store):
        client = TestClient(app_module.create_app(store))
        created.append(client)
        return client

    yield _factory
    for client in created:
        client.__exit__(None, None, None)


VALID_DOC = {
    "version": 1,
    "algorithm": "bcrypt",
    "users": [
        {"username": "pparker", "full_name": "Peter Parker",
         "password_hash": "$2b$04$" + "c" * 53, "rotated_at": None},
        {"username": "rmiller", "full_name": "Rebecca Miller",
         "password_hash": "$2b$04$" + "d" * 53, "rotated_at": None},
    ],
}


# ------------------------------------------------------------- legacy + migrate
def test_legacy_pickle_readable_and_pending(paths):
    original = pickle.dumps(["$2b$12$" + "a" * 53, "$2b$12$" + "b" * 53])
    paths["pickle"].write_bytes(original)
    store = make_store(paths)
    try:
        assert store.source == "legacy-pickle"
        assert store.migration_pending is True
        assert not store.read_only
        assert [u.username for u in store.users] == ["pparker", "rmiller"]
        assert paths["pickle"].read_bytes() == original
    finally:
        store.stop()


def test_first_write_migrates_pickle_to_json(paths):
    original = pickle.dumps(["$2b$12$" + "a" * 53, "$2b$12$" + "b" * 53])
    paths["pickle"].write_bytes(original)
    store = make_store(paths)
    try:
        snap = store.rotate({"pparker": "pw-one", "rmiller": "pw-two"})
        assert snap["source"] == "file"
        assert snap["version"] == 2
        assert paths["cred"].exists()
        doc = json.loads(paths["cred"].read_text(encoding="utf-8"))
        assert doc["version"] == 2 and doc["algorithm"] == "bcrypt"
        assert {u["username"] for u in doc["users"]} == {"pparker", "rmiller"}
        assert paths["pickle"].read_bytes() == original
        leftovers = list(paths["cred"].parent.glob(".credentials.*.tmp"))
        assert leftovers == []
    finally:
        store.stop()

# ------------------------------------------------------------- rollback tests
def test_migration_failure_restores_pre_existing_json(paths):
    make_pickle(paths["pickle"])
    original_doc = dict(VALID_DOC)
    paths["cred"].write_text(json.dumps(original_doc), encoding="utf-8")
    original_bytes = paths["cred"].read_bytes()
    store = make_store(paths)
    store.migration_pending = True  # simulate a mid-flight migration scenario
    calls = {"n": 0}
    real_write = store._atomic_write_json

    def flaky_write(doc):
        calls["n"] += 1
        raise OSError("disk full during migration")

    try:
        store._atomic_write_json = flaky_write
        with pytest.raises(OSError):
            store._ensure_migrated()
        assert paths["cred"].read_bytes() == original_bytes
        assert store.migration_pending is True
        assert calls["n"] == 1
    finally:
        store._atomic_write_json = real_write
        store.stop()


def test_migration_failure_removes_partial_json(paths, monkeypatch):
    make_pickle(paths["pickle"])
    assert not paths["cred"].exists()
    store = make_store(paths, monkeypatch=monkeypatch)
    assert store.migration_pending is True

    real_replace = os.replace
    partial_created = threading.Event()

    def fail_replace(src, dst):
        partial_created.set()
        raise OSError("rename denied")

    monkeypatch.setattr(os, "replace", fail_replace)
    try:
        with pytest.raises(OSError):
            store._ensure_migrated()
    finally:
        monkeypatch.setattr(os, "replace", real_replace)
        store.stop()
    assert not paths["cred"].exists()
    leftovers = [p for p in paths["cred"].parent.glob(".credentials.*.tmp")]
    assert leftovers == []


# ------------------------------------------------- version / algorithm checks
def test_illegal_version_downgrade_at_startup_goes_readonly(paths, monkeypatch):
    paths["cred"].write_text(json.dumps(VALID_DOC), encoding="utf-8")
    store = make_store(paths, monkeypatch=monkeypatch)
    store.stop()
    downgraded = dict(VALID_DOC, version=0)
    paths["cred"].write_text(json.dumps(downgraded), encoding="utf-8")
    store2 = make_store(paths, monkeypatch=monkeypatch)
    try:
        assert store2.read_only is True
        assert "downgrade" in store2.read_only_reason
        with pytest.raises(app_module.ReadOnlyError):
            store2.rotate({"pparker": "x", "rmiller": "y"})
    finally:
        store2.stop()


def test_unsupported_algorithm_goes_readonly(paths, monkeypatch):
    bad = dict(VALID_DOC, algorithm="md5")
    paths["cred"].write_text(json.dumps(bad), encoding="utf-8")
    store = make_store(paths, monkeypatch=monkeypatch)
    try:
        assert store.read_only is True
        assert "algorithm" in store.read_only_reason
    finally:
        store.stop()


def test_hot_reload_rejects_downgrade_and_locks_readonly(paths, monkeypatch):
    paths["cred"].write_text(json.dumps(VALID_DOC), encoding="utf-8")
    store = make_store(paths, watch_interval=0.01, monkeypatch=monkeypatch)
    try:
        assert not store.read_only
        store.rotate({"pparker": "a", "rmiller": "b"})
        current_version = store.version
        assert current_version >= 2
        downgraded = dict(VALID_DOC, version=current_version - 1)
        paths["cred"].write_text(json.dumps(downgraded), encoding="utf-8")
        deadline = time.time() + 3
        while time.time() < deadline and not store.read_only:
            time.sleep(0.02)
        assert store.read_only is True
        assert "downgrade" in store.read_only_reason
    finally:
        store.stop()

# ---------------------------------------------------------- concurrency tests
def test_concurrent_rotations_are_serialized(paths, monkeypatch):
    paths["cred"].write_text(json.dumps(VALID_DOC), encoding="utf-8")
    store = make_store(paths, monkeypatch=monkeypatch)
    errors = []

    def worker(idx):
        try:
            store.rotate({"pparker": f"pw-{idx}-one", "rmiller": f"pw-{idx}-two"})
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors
        assert store.version == 11
        doc = json.loads(paths["cred"].read_text(encoding="utf-8"))
        assert doc["version"] == 11
        assert len(doc["users"]) == 2
        assert all(u["rotated_at"] for u in doc["users"])
        leftovers = list(paths["cred"].parent.glob(".credentials.*.tmp"))
        assert leftovers == []
    finally:
        store.stop()


def test_concurrent_rotations_interprocess_lock_file(paths, monkeypatch):
    paths["cred"].write_text(json.dumps(VALID_DOC), encoding="utf-8")
    store_a = make_store(paths, monkeypatch=monkeypatch)
    store_b = make_store(paths, monkeypatch=monkeypatch)
    order = []
    barrier = threading.Barrier(2)

    def run(store, tag):
        barrier.wait()
        store.rotate({"pparker": f"{tag}-one", "rmiller": f"{tag}-two"})
        order.append(tag)

    try:
        ta = threading.Thread(target=run, args=(store_a, "A"))
        tb = threading.Thread(target=run, args=(store_b, "B"))
        ta.start(); tb.start(); ta.join(30); tb.join(30)
        assert len(order) == 2
        doc = json.loads(paths["cred"].read_text(encoding="utf-8"))
        assert doc["version"] == 3
    finally:
        store_a.stop(); store_b.stop()


# ------------------------------------------------------------- source priority
def test_source_priority_file_over_env_and_config(paths, monkeypatch):
    paths["cred"].write_text(json.dumps(VALID_DOC), encoding="utf-8")
    env_doc = dict(VALID_DOC, version=5)
    config_doc = dict(VALID_DOC, version=6)
    paths["config_dir"].mkdir()
    (paths["config_dir"] / "credentials.json").write_text(
        json.dumps(config_doc), encoding="utf-8")
    store = make_store(paths, env_doc=env_doc)
    try:
        assert store.source == "file"
        assert store.version == 1
    finally:
        store.stop()
        monkeypatch.delenv(paths["env_var"], raising=False)


def test_environment_source_change_does_not_trigger_reload(paths, monkeypatch):
    env_doc = dict(VALID_DOC, version=1)
    store = make_store(paths, env_doc=env_doc, watch_interval=0.01)
    try:
        assert store.source == "environment"
        os.environ[paths["env_var"]] = json.dumps(dict(env_doc, version=9))
        time.sleep(0.3)
        assert store.source == "environment"
        assert store.version == 1
    finally:
        store.stop()
        monkeypatch.delenv(paths["env_var"], raising=False)


def test_hot_reload_picks_up_new_version_within_window(paths, monkeypatch):
    paths["cred"].write_text(json.dumps(VALID_DOC), encoding="utf-8")
    store = make_store(paths, watch_interval=0.01, monkeypatch=monkeypatch)
    try:
        new_doc = dict(VALID_DOC, version=3)
        for user in new_doc["users"]:
            user["rotated_at"] = app_module.utc_now_iso()
        paths["cred"].write_text(json.dumps(new_doc), encoding="utf-8")
        deadline = time.time() + 5
        while time.time() < deadline and store.version != 3:
            time.sleep(0.02)
        assert store.version == 3
        assert store.rotated_at is not None
    finally:
        store.stop()

# ------------------------------------------------------------------- endpoints
class StdinStub:
    def __init__(self, text):
        self._buf = io.StringIO(text)

    def readline(self):
        return self._buf.readline()


def test_rotate_endpoint_reads_only_from_stdin(paths, monkeypatch, client_factory):
    paths["cred"].write_text(json.dumps(VALID_DOC), encoding="utf-8")
    store = make_store(paths, monkeypatch=monkeypatch)
    client = client_factory(store)
    monkeypatch.delenv("PPARKER_PW", raising=False)
    monkeypatch.setattr(app_module.sys, "stdin", StdinStub("s3cret-one\ns3cret-two\n"))
    with client:
        res = client.post("/keys/rotate", json={"pparker": "ignored-body"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["state"]["version"] == 2
    assert body["state"]["rotated_at_local"].endswith("UTC+8")
    store.stop()


def test_verify_endpoint_roundtrip(paths, monkeypatch, client_factory):
    from app import hash_passphrase

    doc = {
        "version": 1,
        "algorithm": "bcrypt",
        "users": [
            {"username": "pparker", "full_name": "Peter Parker",
             "password_hash": hash_passphrase("correct horse"), "rotated_at": None},
            {"username": "rmiller", "full_name": "Rebecca Miller",
             "password_hash": hash_passphrase("other horse"), "rotated_at": None},
        ],
    }
    paths["cred"].write_text(json.dumps(json.loads(json.dumps(doc))), encoding="utf-8")
    store = make_store(paths, monkeypatch=monkeypatch)
    client = client_factory(store)
    with client:
        monkeypatch.setattr(app_module.sys, "stdin", StdinStub("pparker:correct horse\n"))
        good = client.post("/keys/verify")
        assert good.status_code == 200 and good.json()["valid"] is True

        monkeypatch.setattr(app_module.sys, "stdin", StdinStub("pparker:wrong\n"))
        bad = client.post("/keys/verify")
        assert bad.status_code == 401 and bad.json()["valid"] is False

        monkeypatch.setattr(app_module.sys, "stdin", StdinStub("garbage\n"))
        malformed = client.post("/keys/verify")
        assert malformed.status_code == 400
    store.stop()


def test_readonly_returns_409_and_panel_badge(paths, monkeypatch, client_factory):
    bad = dict(VALID_DOC, algorithm="sha1")
    paths["cred"].write_text(json.dumps(bad), encoding="utf-8")
    store = make_store(paths, monkeypatch=monkeypatch)
    client = client_factory(store)
    with client:
        assert store.read_only is True
        monkeypatch.setattr(app_module.sys, "stdin", StdinStub("a\nb\n"))
        rotate = client.post("/keys/rotate")
        assert rotate.status_code == 409
        assert rotate.json()["error"] == "read-only"

        monkeypatch.setattr(app_module.sys, "stdin", StdinStub("pparker:x\n"))
        verify = client.post("/keys/verify")
        assert verify.status_code == 409

        panel = client.get("/")
        assert panel.status_code == 200
        html = panel.text
        assert "只读 READ-ONLY" in html
        assert "ro" in html

        state = client.get("/keys/state").json()
        assert state["read_only"] is True
        assert "algorithm" in state["read_only_reason"]
    store.stop()


def test_panel_shows_readwrite_badge_and_rotation_time(paths, monkeypatch, client_factory):
    paths["cred"].write_text(json.dumps(VALID_DOC), encoding="utf-8")
    store = make_store(paths, monkeypatch=monkeypatch)
    client = client_factory(store)
    with client:
        html = client.get("/").text
        assert "可读写 READ-WRITE" in html
        monkeypatch.setattr(app_module.sys, "stdin", StdinStub("one\ntwo\n"))
        client.post("/keys/rotate")
        html2 = client.get("/").text
        snap = client.get("/keys/state").json()
        assert snap["rotated_at_local"] != "—"
        stamp = snap["rotated_at_local"]
        assert stamp.split(" ")[0] in html2
    store.stop()