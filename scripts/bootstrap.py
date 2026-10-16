"""Bootstrap the Purple Team lab for a fresh clone: generate .env secrets if
missing (including the Wazuh indexer bcrypt hashes internal_users.yml needs
to actually accept them), bring the stack up, and print a copy-paste
credentials block. See work/school/Purple Team Project.md's 2026-08-04
"deployment-UX decision" for why this is a terminal+file flow rather than an
in-app login banner (purple_dashboard's HTTP Basic Auth intercepts before any
custom HTML can render).
"""
import os
import re
import secrets
import string
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
ENV_EXAMPLE_PATH = PROJECT_ROOT / ".env.example"
INTERNAL_USERS_PATH = PROJECT_ROOT / "wazuh" / "config" / "wazuh_indexer" / "internal_users.yml"
QUICKSTART_PATH = PROJECT_ROOT / "QUICKSTART_CREDENTIALS.md"
WAZUH_DIR = PROJECT_ROOT / "wazuh"
CERTS_DIR = WAZUH_DIR / "config" / "wazuh_indexer_ssl_certs"
AUTHD_PASS_PATH = WAZUH_DIR / "config" / "wazuh_cluster" / "authd.pass"
# Gitignored private keys every fresh clone must generate (wazuh/README.md step 2).
CERT_KEY_FILES = (
    "root-ca.key",
    "admin-key.pem",
    "wazuh.indexer-key.pem",
    "wazuh.manager-key.pem",
    "wazuh.dashboard-key.pem",
)

WAZUH_INDEXER_IMAGE = "wazuh/wazuh-indexer:4.9.2"
# No "$": docker compose interpolates it in .env and silently truncates the password.
COMPLEX_PASSWORD_SPECIALS = "@!%*?&-_"

# .env keys this script fills when blank. Every one of these already has a
# "no default, refuses to start without it" comment in .env.example.
GENERATED_KEYS = (
    "INTERNAL_ACTION_TOKEN",
    "ROUND_HELPER_TOKEN",
    "DASHBOARD_AUTH_TOKEN",
    "DASHBOARD_RED_ACTION_TOKEN",
    "DASHBOARD_BLUE_ACTION_TOKEN",
    "DASHBOARD_INFRA_ACTION_TOKEN",
    "WAZUH_INDEXER_PASSWORD",
    "WAZUH_DASHBOARD_PASSWORD",
    "WAZUH_API_PASSWORD",
)


def generate_hex_secret(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)


def generate_complex_password(length: int = 24) -> str:
    # wazuh.manager's wazuh-wui user requires 8+ chars with at least one
    # uppercase, one lowercase, one digit, and one of @$!%*?&-_. Guarantee
    # one of each class, then fill the rest randomly and shuffle so the
    # required chars aren't predictably in fixed positions.
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(COMPLEX_PASSWORD_SPECIALS),
    ]
    alphabet = string.ascii_letters + string.digits + COMPLEX_PASSWORD_SPECIALS
    rest = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + rest
    # Fisher-Yates via secrets, not random.shuffle (which isn't CSPRNG-backed).
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def render_env_file(template_text: str, values: dict) -> str:
    lines = template_text.splitlines(keepends=True)
    out = []
    for line in lines:
        stripped = line.rstrip("\n")
        match = re.fullmatch(r"([A-Z_]+)=", stripped)
        if match and match.group(1) in values:
            newline = "\n" if line.endswith("\n") else ""
            out.append(f"{match.group(1)}={values[match.group(1)]}{newline}")
        else:
            out.append(line)
    return "".join(out)


def extract_bcrypt_hash(text: str) -> str:
    match = re.search(r"\$2[aby]\$\S+", text)
    if not match:
        raise ValueError("no bcrypt hash found in hash.sh output")
    return match.group(0)


def generate_wazuh_hash(password: str, run=subprocess.run) -> str:
    # The password is passed as an argv literal (hash.sh -p <password>) --
    # stdin-piping isn't a verified-safe alternative for this specific tool,
    # so instead we make sure a failure can't leak it back out: catch here
    # and raise a redacted error instead of letting the original exception
    # (whose str() includes the full argv, password included) surface raw.
    # SubprocessError (not just CalledProcessError) so a future timeout=
    # addition -- TimeoutExpired also embeds argv -- stays covered too.
    # The redacted RuntimeError is raised *outside* this except block on
    # purpose: `raise ... from None` only suppresses the original exception
    # from *display*, it doesn't clear __context__ -- a raise still
    # lexically inside the except block leaves the password-bearing
    # original reachable via exc.__context__ to anything that walks the
    # exception chain programmatically, not just the default traceback
    # formatter.
    hash_failed = False
    try:
        result = run(
            [
                "docker", "run", "--rm",
                "-e", "JAVA_HOME=/usr/share/wazuh-indexer/jdk",
                "--entrypoint", "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh",
                WAZUH_INDEXER_IMAGE,
                "-p", password,
            ],
            capture_output=True, text=True, check=True,
        )
    except subprocess.SubprocessError:
        hash_failed = True
    if hash_failed:
        raise RuntimeError(
            "hash.sh failed while generating a Wazuh credential hash "
            "(command and output redacted to avoid leaking the plaintext password)"
        )
    return extract_bcrypt_hash(result.stdout)


def update_internal_users_hashes(yml_text: str, admin_hash: str, kibanaserver_hash: str) -> str:
    hashes = {"admin": admin_hash, "kibanaserver": kibanaserver_hash}
    counts = {name: 0 for name in hashes}
    section = None
    out = []
    for line in yml_text.splitlines(keepends=True):
        top_level = re.fullmatch(r"(\w+):\s*\n?", line)
        if top_level and not line.startswith((" ", "\t")):
            section = top_level.group(1)
            out.append(line)
            continue
        if section in hashes and re.fullmatch(r'\s*hash:\s*"[^"]*"\s*\n?', line):
            indent = line[: len(line) - len(line.lstrip())]
            newline = "\n" if line.endswith("\n") else ""
            out.append(f'{indent}hash: "{hashes[section]}"{newline}')
            counts[section] += 1
            continue
        out.append(line)
    for name, count in counts.items():
        if count != 1:
            raise ValueError(
                f"expected exactly one hash replacement in the '{name}' section of "
                f"internal_users.yml, found {count} -- .env's rotated password would "
                f"be out of sync with the actual bcrypt hash"
            )
    return "".join(out)


def build_credentials_block(env: dict) -> str:
    return f"""Purple Team Lab -- Logins
=========================

1. Target (the vulnerable app red attacks)
   URL:       http://localhost:5000
   Staff URL: http://localhost:5000/admin/login
   Logins:    admin / admin123   or   jsmith / Sunshine2024!
              (seeded and deliberately weak -- not generated)

2. Round Control Dashboard (start/stop rounds, clear flags)
   URL:      http://localhost:8080
   Username: operator
   Password: {env.get("DASHBOARD_AUTH_TOKEN", "<missing>")}

   Logging in only lets you view. Each action needs its own token,
   pasted into that action's token field:
     Start round (Infra): {env.get("DASHBOARD_INFRA_ACTION_TOKEN", "<missing>")}
     Red action:          {env.get("DASHBOARD_RED_ACTION_TOKEN", "<missing>")}
     Blue action:         {env.get("DASHBOARD_BLUE_ACTION_TOKEN", "<missing>")}

3. Wazuh Dashboard (SIEM -- browser warns on the self-signed cert; proceed)
   URL:      https://localhost
   Username: admin
   Password: {env.get("WAZUH_INDEXER_PASSWORD", "<missing>")}

Referee report (after a round):
   docker exec purple-lab-referee tail -n 5 /app/referee_logs/referee_assessments.jsonl
"""


def _write_owner_only(path: Path, text: str) -> None:
    # os.open's mode is applied atomically at creation, unlike write_text()
    # followed by a separate chmod call, which leaves a brief window where
    # the plaintext-secrets file has the default (wider) permissions.
    # Real restriction only applies on POSIX -- Windows has no equivalent
    # to owner/group/other bits, so this (and any chmod call) is a no-op
    # there; callers are responsible for warning the user on that platform.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    # os.open's mode is only applied when O_CREAT actually creates the file
    # -- POSIX ignores it if path already existed, so a stale wider-than-
    # 0o600 file (e.g. from a pre-patch version of this script) would
    # otherwise never get re-narrowed on a later run.
    if os.name == "posix":
        os.chmod(path, 0o600)


def _parse_env(text: str) -> dict:
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Z_]+)=(.*)", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def bootstrap_env(run=subprocess.run) -> dict:
    if ENV_PATH.exists():
        # Hardens a pre-existing .env too (hand-copied, or created by an
        # older pre-patch version of this script) -- not just first-generation.
        if os.name == "posix":
            os.chmod(ENV_PATH, 0o600)
        return _parse_env(ENV_PATH.read_text(encoding="utf-8"))

    if os.name != "posix":
        print(
            f"warning: file permissions are not enforced on this platform -- "
            f"{ENV_PATH} and {QUICKSTART_PATH} will contain plaintext secrets "
            "readable by any local account with filesystem access"
        )

    values = {
        "INTERNAL_ACTION_TOKEN": generate_hex_secret(),
        "ROUND_HELPER_TOKEN": generate_hex_secret(),
        "DASHBOARD_AUTH_TOKEN": generate_hex_secret(),
        "DASHBOARD_RED_ACTION_TOKEN": generate_hex_secret(),
        "DASHBOARD_BLUE_ACTION_TOKEN": generate_hex_secret(),
        "DASHBOARD_INFRA_ACTION_TOKEN": generate_hex_secret(),
        "WAZUH_INDEXER_PASSWORD": generate_hex_secret(24),
        "WAZUH_DASHBOARD_PASSWORD": generate_hex_secret(24),
        "WAZUH_API_PASSWORD": generate_complex_password(),
    }

    admin_hash = generate_wazuh_hash(values["WAZUH_INDEXER_PASSWORD"], run=run)
    kibanaserver_hash = generate_wazuh_hash(values["WAZUH_DASHBOARD_PASSWORD"], run=run)
    updated_yml = update_internal_users_hashes(
        INTERNAL_USERS_PATH.read_text(encoding="utf-8"), admin_hash, kibanaserver_hash
    )
    INTERNAL_USERS_PATH.write_text(updated_yml, encoding="utf-8")

    env_text = render_env_file(ENV_EXAMPLE_PATH.read_text(encoding="utf-8"), values)
    _write_owner_only(ENV_PATH, env_text)

    return values


def _clear_docker_placeholder(path: Path) -> None:
    # If compose runs before a bind-mounted file exists, Docker creates an
    # empty directory in its place, and every later mount fails or reads
    # nothing. rmdir only succeeds on an empty dir, so real data is safe.
    if path.is_dir():
        path.rmdir()


def ensure_wazuh_files(run=subprocess.run) -> None:
    _clear_docker_placeholder(AUTHD_PASS_PATH)
    if not AUTHD_PASS_PATH.exists():
        print(f"Generating agent-enrollment key at {AUTHD_PASS_PATH}...")
        _write_owner_only(AUTHD_PASS_PATH, generate_hex_secret())

    key_paths = [CERTS_DIR / name for name in CERT_KEY_FILES]
    for path in key_paths:
        _clear_docker_placeholder(path)
    if not all(path.is_file() for path in key_paths):
        print("Generating Wazuh TLS certificates...")
        run(
            ["docker", "compose", "-f", "generate-indexer-certs.yml", "run", "--rm", "generator"],
            cwd=WAZUH_DIR,
            check=True,
        )


def main() -> int:
    env = bootstrap_env()
    ensure_wazuh_files()

    print("Bringing the stack up (docker compose up -d)...")
    subprocess.run(["docker", "compose", "up", "-d"], cwd=PROJECT_ROOT, check=True)

    block = build_credentials_block(env)
    print("\n" + block)
    _write_owner_only(QUICKSTART_PATH, block)
    print(f"Also saved to {QUICKSTART_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
