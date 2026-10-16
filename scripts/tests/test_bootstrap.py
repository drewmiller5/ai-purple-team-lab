import os
import re
import stat
import subprocess
from pathlib import Path

import scripts.bootstrap as bootstrap
from scripts.bootstrap import (
    GENERATED_KEYS,
    build_credentials_block,
    extract_bcrypt_hash,
    generate_complex_password,
    generate_hex_secret,
    generate_wazuh_hash,
    render_env_file,
    update_internal_users_hashes,
)


def test_generate_hex_secret_is_64_hex_chars_and_random():
    a = generate_hex_secret()
    b = generate_hex_secret()
    assert re.fullmatch(r"[0-9a-f]{64}", a)
    assert a != b


def test_generate_complex_password_satisfies_wazuh_manager_rule():
    # wazuh.manager's complexity rule: 8+ chars, at least one uppercase,
    # one lowercase, one digit, one of @$!%*?&-_
    for _ in range(20):
        pw = generate_complex_password()
        assert len(pw) >= 8
        assert re.search(r"[A-Z]", pw)
        assert re.search(r"[a-z]", pw)
        assert re.search(r"[0-9]", pw)
        assert re.search(r"[@$!%*?&\-_]", pw)


def test_generate_complex_password_is_random():
    assert generate_complex_password() != generate_complex_password()


def test_render_env_file_fills_only_blank_target_keys():
    template = (
        "# comment stays\n"
        "INTERNAL_ACTION_TOKEN=\n"
        "\n"
        "# OLLAMA_MODEL=qwen2.5:7b\n"
        "DASHBOARD_AUTH_TOKEN=\n"
        "UNRELATED_KEY=\n"
    )
    values = {"INTERNAL_ACTION_TOKEN": "abc123", "DASHBOARD_AUTH_TOKEN": "def456"}

    result = render_env_file(template, values)

    assert "INTERNAL_ACTION_TOKEN=abc123" in result
    assert "DASHBOARD_AUTH_TOKEN=def456" in result
    assert "# comment stays" in result
    assert "# OLLAMA_MODEL=qwen2.5:7b" in result
    assert "UNRELATED_KEY=\n" in result  # not in values -- left blank, untouched


def test_extract_bcrypt_hash_pulls_hash_out_of_noisy_output():
    noisy = (
        "WARNING: some docker log noise\n"
        "Password:\n"
        "$2y$12$V0VNqbU4MQVcz4migwmlyeS5y/gNYuLpxz.PouGMDx6unAfYQyZIG\n"
    )
    assert extract_bcrypt_hash(noisy) == (
        "$2y$12$V0VNqbU4MQVcz4migwmlyeS5y/gNYuLpxz.PouGMDx6unAfYQyZIG"
    )


def test_extract_bcrypt_hash_raises_when_no_hash_present():
    try:
        extract_bcrypt_hash("no hash here\n")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_update_internal_users_hashes_only_touches_admin_and_kibanaserver():
    yml = (
        "admin:\n"
        '  hash: "$2y$12$OLDADMINHASH"\n'
        "  reserved: true\n"
        "\n"
        "kibanaserver:\n"
        '  hash: "$2y$12$OLDKIBANAHASH"\n'
        "  reserved: true\n"
        "\n"
        "kibanaro:\n"
        '  hash: "$2a$12$UNTOUCHEDHASH"\n'
        "  reserved: false\n"
    )

    result = update_internal_users_hashes(
        yml, admin_hash="$2y$12$NEWADMIN", kibanaserver_hash="$2y$12$NEWKIBANA"
    )

    assert '  hash: "$2y$12$NEWADMIN"' in result
    assert '  hash: "$2y$12$NEWKIBANA"' in result
    assert '  hash: "$2a$12$UNTOUCHEDHASH"' in result  # kibanaro untouched
    assert "OLDADMINHASH" not in result
    assert "OLDKIBANAHASH" not in result


def test_update_internal_users_hashes_raises_if_a_section_never_matched():
    # admin's hash line uses single quotes -- doesn't match the expected
    # `hash: "..."` shape, so the replacement silently never fires.
    yml = (
        "admin:\n"
        "  hash: 'not-the-expected-format'\n"
        "  reserved: true\n"
        "\n"
        "kibanaserver:\n"
        '  hash: "$2y$12$OLDKIBANAHASH"\n'
        "  reserved: true\n"
    )

    try:
        update_internal_users_hashes(
            yml, admin_hash="$2y$12$NEWADMIN", kibanaserver_hash="$2y$12$NEWKIBANA"
        )
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "admin" in str(exc)


def test_update_internal_users_hashes_raises_if_section_missing_entirely():
    yml = 'kibanaserver:\n  hash: "$2y$12$OLDKIBANAHASH"\n'

    try:
        update_internal_users_hashes(
            yml, admin_hash="$2y$12$NEWADMIN", kibanaserver_hash="$2y$12$NEWKIBANA"
        )
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "admin" in str(exc)


def test_build_credentials_block_includes_every_surface():
    env = {
        "DASHBOARD_AUTH_TOKEN": "dashtoken123",
        "WAZUH_INDEXER_PASSWORD": "indexerpass123",
        "WAZUH_API_PASSWORD": "apipass123",
    }

    block = build_credentials_block(env)

    assert "localhost:5000" in block  # target
    assert "admin123" in block  # seeded target staff creds
    assert "localhost:8080" in block  # round control dashboard
    assert "operator" in block and "dashtoken123" in block
    assert "localhost:443" in block or "localhost" in block  # wazuh dashboard
    assert "indexerpass123" in block
    # No raw indexer/manager API endpoints (9200/55000): not published to
    # the host -- debugging convenience only, dropped after the ports
    # themselves were removed from docker-compose.yml for being flaky
    # across Docker Desktop engine restarts and unneeded by the experiment.
    assert "9200" not in block
    assert "55000" not in block


def test_generated_keys_cover_every_blank_key_in_the_real_env_example():
    """Regression test: GENERATED_KEYS drifted out of sync with
    .env.example when ROUND_HELPER_TOKEN was added elsewhere (H54) --
    render_env_file only fills a line whose key is in GENERATED_KEYS, so a
    fresh clone's quickstart silently left ROUND_HELPER_TOKEN blank and
    docker compose then refused to start. Every blank `KEY=` line in the
    real .env.example must be covered by GENERATED_KEYS."""
    text = bootstrap.ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
    blank_keys = {
        match.group(1)
        for line in text.splitlines()
        for match in [re.fullmatch(r"([A-Z_]+)=", line)]
        if match
    }
    assert blank_keys == set(GENERATED_KEYS)


def test_write_owner_only_writes_content_with_no_write_then_chmod_window(tmp_path):
    # Must create the file already-restricted (os.open with mode=0o600), not
    # write_text() followed by a separate chmod call -- the latter leaves a
    # window where the plaintext-secrets file briefly has default (wider)
    # permissions. Real enforcement only applies on POSIX; Windows has no
    # equivalent to owner/group/other bits.
    path = tmp_path / "secret.txt"

    bootstrap._write_owner_only(path, "hello")

    assert path.read_text(encoding="utf-8") == "hello"
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_write_owner_only_re_narrows_permissions_on_a_pre_existing_wider_file(tmp_path):
    # os.open()'s mode argument is only applied when O_CREAT actually
    # creates the file -- POSIX ignores it if the path already exists, so
    # a stale, wider-than-0o600 file (e.g. left by a pre-patch version of
    # this script) would otherwise never get re-narrowed on a later run.
    path = tmp_path / "secret.txt"
    path.write_text("old", encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o644)

    bootstrap._write_owner_only(path, "new")

    assert path.read_text(encoding="utf-8") == "new"
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_bootstrap_env_restricts_permissions_on_the_idempotent_path_too(tmp_path, monkeypatch):
    # A pre-existing .env (hand-copied, or created by an older pre-patch
    # version of this script) must also get hardened, not just first-generation.
    env_path = tmp_path / ".env"
    env_path.write_text("INTERNAL_ACTION_TOKEN=existing-value\n", encoding="utf-8")
    monkeypatch.setattr(bootstrap, "ENV_PATH", env_path)

    bootstrap.bootstrap_env(run=lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not shell out")))

    if os.name == "posix":
        assert stat.S_IMODE(env_path.stat().st_mode) == 0o600


def test_generate_wazuh_hash_redacts_password_on_docker_failure():
    password = "SuperSecretPW123!"

    def failing_run(argv, **kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=argv, output="", stderr="boom")

    try:
        generate_wazuh_hash(password, run=failing_run)
        assert False, "expected an exception"
    except Exception as exc:
        assert password not in str(exc)
        assert password not in repr(exc)
        assert exc.__cause__ is None  # not chained -- avoids leaking argv via traceback
        # `from None` only suppresses *display* of the original exception;
        # __context__ stays populated unless the raise happens outside the
        # except block entirely. Any code walking the exception chain
        # programmatically (not just the default traceback formatter) must
        # not be able to recover the plaintext-password-bearing original.
        assert exc.__context__ is None


def test_bootstrap_env_is_idempotent_when_env_already_exists(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("INTERNAL_ACTION_TOKEN=existing-value\n", encoding="utf-8")
    monkeypatch.setattr(bootstrap, "ENV_PATH", env_path)

    calls = []
    values = bootstrap.bootstrap_env(run=lambda *a, **k: calls.append(a))

    assert values == {"INTERNAL_ACTION_TOKEN": "existing-value"}
    assert calls == []  # never shells out to docker when .env already exists


def test_bootstrap_env_generates_and_syncs_hashes_when_missing(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_example_path = tmp_path / ".env.example"
    internal_users_path = tmp_path / "internal_users.yml"
    env_example_path.write_text(
        "\n".join(f"{k}=" for k in GENERATED_KEYS) + "\n", encoding="utf-8"
    )
    internal_users_path.write_text(
        'admin:\n  hash: "$2y$12$OLD"\n\nkibanaserver:\n  hash: "$2y$12$OLD"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(bootstrap, "ENV_PATH", env_path)
    monkeypatch.setattr(bootstrap, "ENV_EXAMPLE_PATH", env_example_path)
    monkeypatch.setattr(bootstrap, "INTERNAL_USERS_PATH", internal_users_path)

    def fake_run(argv, **kwargs):
        assert argv[:2] == ["docker", "run"]
        return subprocess.CompletedProcess(argv, 0, stdout="$2y$12$FAKEHASH", stderr="")

    values = bootstrap.bootstrap_env(run=fake_run)

    assert set(values) == set(GENERATED_KEYS)
    assert env_path.exists()
    written = env_path.read_text(encoding="utf-8")
    for key in GENERATED_KEYS:
        assert f"{key}={values[key]}" in written
    assert '"$2y$12$FAKEHASH"' in internal_users_path.read_text(encoding="utf-8")
    assert "OLD" not in internal_users_path.read_text(encoding="utf-8")


def test_generate_complex_password_never_contains_dollar():
    # docker compose interpolates "$" in .env, silently truncating the password.
    for _ in range(200):
        assert "$" not in generate_complex_password()


def _point_wazuh_paths_at(tmp_path, monkeypatch):
    certs = tmp_path / "certs"
    certs.mkdir()
    authd = tmp_path / "cluster" / "authd.pass"
    authd.parent.mkdir()
    monkeypatch.setattr(bootstrap, "CERTS_DIR", certs)
    monkeypatch.setattr(bootstrap, "AUTHD_PASS_PATH", authd)
    monkeypatch.setattr(bootstrap, "WAZUH_DIR", tmp_path)
    return certs, authd


def test_ensure_wazuh_files_replaces_docker_placeholder_dirs(tmp_path, monkeypatch):
    certs, authd = _point_wazuh_paths_at(tmp_path, monkeypatch)
    authd.mkdir()  # what Docker leaves behind when compose ran first
    (certs / "wazuh.indexer-key.pem").mkdir()
    calls = []

    bootstrap.ensure_wazuh_files(run=lambda argv, **k: calls.append(argv))

    assert authd.is_file() and re.fullmatch(r"[0-9a-f]{64}", authd.read_text())
    assert not (certs / "wazuh.indexer-key.pem").exists()
    assert calls and "generate-indexer-certs.yml" in calls[0]


def test_ensure_wazuh_files_leaves_existing_files_alone(tmp_path, monkeypatch):
    certs, authd = _point_wazuh_paths_at(tmp_path, monkeypatch)
    authd.write_text("existing-key")
    for name in bootstrap.CERT_KEY_FILES:
        (certs / name).write_text("key")
    calls = []

    bootstrap.ensure_wazuh_files(run=lambda argv, **k: calls.append(argv))

    assert authd.read_text() == "existing-key"
    assert calls == []  # no cert regeneration when every key already exists
