# Purple Team AI Lab

### For Research and Educational Use Only.

## Why I Built This

Commercial AI is assumed to be better at defense than offense with content filtering and ethical alignment are supposed to suppress attack capability while leaving detection intact. That's a theoretical assumption, never actually tested. This is a live purple-team lab, built for IT567 (Global Cybersecurity and Cyber Warfare), that tests it directly: a red-team AI with a single target on an internal host, a blue-team AI defending it, both running continuously and asynchronously that is not turn-based and not scripted to be fair to each other, because real conflict isn't either.

My working assumption going in was that defense would hold the advantage, since most AI training and most cyber roles skew defensive. This lab exists to test whether that holds.

Building it was grueling the recent bug-bounty and fix cycle alone took a lot out of me, on top of just getting the project off the ground. What I found: AI is more capable at both offense then what it is given it credit for. After finishing the project I did a second bug-bounty pass after the repo had been live as a way to improve it to the standard I wanted it to be.

## How It Works

Two Ollama-driven agents fight over a real, deliberately vulnerable Flask app, with a referee judging the round and a live dashboard to watch or play along:

| Component | Role |
|---|---|
| `target/` | The attack surface — a small "Meridian Logistics" freight-tracking site with four seeded vulnerabilities (SQLi, weak/no-lockout admin login, IDOR, OS command injection). No advance knowledge is given to red; it's a real black box. |
| `red_agent/` | Ollama-driven attacker loop. Starts with nothing but a URL. Recon → find a seeded vuln → foothold → escalate, consulting its own memory of what's worked before. |
| `blue_agent/` | Reasons over real Wazuh SIEM alerts and decides whether to escalate — ban an IP, lock an account, kill a session — via Wazuh's Active Response layer, which does most of the actual defending natively. |
| `referee/` | Judges each round (decisive win / timeout), assigns red's next target vulnerability via a white-team memory that tracks what's already been found, and prevents stale state from bleeding into a new round. |
| `purple_dashboard/` (`dashboard/`) | Live observability at `localhost:8080` — five tabs (red/blue/white/advisor/combined ledger), a purple-team AI advisor, and a manual-play mode so a human can fire the same red/blue actions the agents do. |
| `round_helper/` | A narrowly-scoped control plane (the only container with `docker.sock` access) for restarting containers between rounds. |
| Wazuh stack | Manager, indexer, and dashboard — real SIEM detection against custom Sigma-style rules (`wazuh-rules/`) written for the four seeded vulns. |
| `shared/` | The persistence layer both agents build on — append-only event log, per-side memory files. |

Everything runs on an isolated Docker bridge network with no internet egress — the target and red agent can't reach anything real, by design. Both agents run on free, local Ollama models (`qwen2.5:7b` by default), so the experiment itself is zero-cost by construction, not just low-stakes in theory.

Full architecture rationale: `docs/design.md`.

## Quickstart

    pipenv run python scripts/bootstrap.py

Generates `.env` with random secrets if it doesn't exist yet (including syncing Wazuh's indexer password hashes into its config — a plain env var alone isn't enough for those), generates the Wazuh TLS certs and agent-enrollment key if missing (and clears the empty placeholder folders Docker leaves when `compose up` ran first), brings the full stack up, and prints a copy-paste credentials block for every login surface (target's seeded staff creds, the dashboard, Wazuh). Also saves that block to `QUICKSTART_CREDENTIALS.md` (gitignored). Safe to re-run — never touches an `.env` that already exists.

## Local dev (no Docker)

    pipenv install --dev
    pipenv run pytest

    # run just the target app
    pipenv run python -m target.app

## Manual Docker setup

Requires `INTERNAL_ACTION_TOKEN`, `ROUND_HELPER_TOKEN`, `DASHBOARD_AUTH_TOKEN`, and three dashboard action tokens (below) — all fail-closed, no defaults. Copy `.env.example` to `.env` and fill in values, or let `scripts/bootstrap.py` generate them:

    cp .env.example .env   # then edit .env
    docker compose up --build

## Dashboard (host port 8080)

Served at `http://localhost:8080` behind HTTP Basic Auth (`DASHBOARD_AUTH_TOKEN`, username `operator`) — plaintext, no TLS, an acceptable trade-off for a local single-operator lab, but the port should never be bound to a routable interface.

**Separation of duties:** viewing the dashboard, firing a red action, firing a blue action, and starting a round (which reaches `round_helper`'s `docker.sock`-backed control plane) are four separate privilege domains, each gated by its own token (`DASHBOARD_AUTH_TOKEN`, `DASHBOARD_RED_ACTION_TOKEN`, `DASHBOARD_BLUE_ACTION_TOKEN`, `DASHBOARD_INFRA_ACTION_TOKEN`). A leaked token grants at most one capability. `scripts/bootstrap.py` generates all four automatically.

## Target app (host port 5000) — the attack surface itself

Reachable at `http://localhost:5000` (bound to `127.0.0.1` only, via a forwarding-only `target-relay` container) so a human can manually try the four seeded vulnerabilities, not just watch `red_agent` do it. No auth in front of it — that's intentional, it's the thing being attacked. `target` itself never has a published port or real network egress of its own.

## Security notes

- Wazuh credentials are rotated, externally-supplied values from `.env`, not the upstream demo defaults. Manager/dashboard host ports are bound to `127.0.0.1` only; the raw indexer/manager APIs (9200, 55000) aren't published to the host at all. Agent enrollment requires a locally-generated pre-shared key. `red_agent` has no access to the Wazuh network — only `target` does.
- No TLS termination anywhere (known, accepted gap for a genuinely local-only deployment).
- The target's four seeded vulnerabilities are intentional — that's the point of the lab. Unintentional findings (a hardcoded session key, unsanitized alert data reaching the blue agent's LLM context) are fixed.
- `127.0.0.1`-only binding can behave inconsistently under Docker Desktop/WSL2's "mirrored" networking mode — if in doubt, verify from another device on the LAN rather than assuming.

Full detail: `docs/ledger/plans/2026-07-28-plan-3c-findings-ledger.md`.

## Process — how this actually got built

This wasn't a single build-and-ship pass. It went through two full bug-bounty hunts (one before the first public push, one after the repo had been live a while) against every component, then a TDD + dual-independent-review fix loop on everything either one found — every fix has a failing test written first and gets reviewed by two independent passes before it's marked closed. The full findings ledger, including what's still open and why, is tracked in `docs/ledger/` rather than hidden — a transparent in-progress roadmap, not a claim that this is bug-free. This project in nearing the end as I am looking forward to what will be built next this fall. 

## What's Built

- `target/` — Flask attack surface, four seeded vulnerabilities, each with a regression test proving it's exploitable.
- `red_agent/` / `blue_agent/` — the two Ollama-driven agent loops, each with their own persisted memory (`shared/memory.py`) and event log (`shared/event_log.py`).
- `referee/` — round judging, win conditions, white-team flag assignment (`referee/white_memory.py`).
- `dashboard/` — live 5-tab observability UI, manual-play mode, purple-team AI advisor.
- `round_helper/` — scoped round-restart control plane.
- `wazuh-rules/` — custom detection rules for the seeded vulnerabilities (`docs/detection-rules.md` has the readable writeup).
- `scripts/bootstrap.py` — one-command setup with generated secrets and a credentials printout.
- `scripts/capture_checkpoint.py` — snapshots memory + event log into `archive/vN/`, a visible learning-curve record over time.
- `docker-compose.yml` — the full isolated-network stack, no internet egress anywhere.

## Future work

- **Try a stronger/newer model.** Both agents run on `OLLAMA_MODEL` (env var, defaults to `qwen2.5:7b`). Current round-timing constants were tuned against that model's pace, so a bigger model needs its own re-tuning pass, not just a swap — but seeing whether the offense-defense balance shifts as the underlying model gets stronger (`qwen3:30b` looks like a good next step) is a natural next experiment.
