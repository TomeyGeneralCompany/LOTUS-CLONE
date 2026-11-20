#!/usr/bin/env python3
"""Local, read-only AutoHack acceptance checks.

Never probes bounty targets, runs target code, or submits reports.
Produces machine-readable pass/fail evidence for local deployment.
"""
from __future__ import annotations
import json
import argparse
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RESULTS: dict[str, dict] = {}

def record(name: str, ok: bool, detail: str) -> None:
    RESULTS[name] = {"passed": ok, "detail": detail}

def run(name: str, args: list[str], timeout: int = 120, env: dict | None = None) -> None:
    if "--offline" not in sys.argv:
        print("Checking " + name + "...", file=sys.stderr, flush=True)
    try:
        proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=env)
        record(name, proc.returncode == 0, (proc.stdout + proc.stderr)[-1200:])
    except (OSError, subprocess.TimeoutExpired) as exc:
        record(name, False, str(exc))

def runtime_settings() -> dict:
    """Use the application's dotenv parser without exporting secrets."""
    proc = subprocess.run(["node", "--import", "tsx", "scripts/runtime-settings.ts"],
                          cwd=ROOT, capture_output=True, text=True, timeout=20)
    if proc.returncode:
        raise ValueError("Cannot read runtime settings; install Node dependencies first")
    return json.loads(proc.stdout)


def emit(args, profile: str) -> int:
    result = {"profile": profile, "production_verified": False, "checks": RESULTS}
    if args.report:
        path = Path(args.report).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if all(check["passed"] for check in RESULTS.values()) else 1


def main() -> int:
    RESULTS.clear()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true",
                        help="Run isolated regressions only; does not establish host/provider readiness")
    parser.add_argument("--model-only", action="store_true",
                        help="Only rerun the deterministic analysis and review regression checks")
    parser.add_argument("--provider", action="store_true",
                        help="Also make one read-only authenticated HackerOne account request")
    parser.add_argument("--report", help="Write acceptance evidence as a private JSON file")
    args = parser.parse_args()
    if args.offline and args.provider:
        parser.error("--provider cannot be combined with --offline")
    if args.model_only and (args.offline or args.provider):
        parser.error("--model-only cannot be combined with --offline or --provider")
    if not args.model_only:
        run("python_integration_tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"])
        if not args.offline:
            run("source_reproduction_languages", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_source_reproduction.py", "-v"],
                env={**os.environ,"TOMEY_REPRODUCTION_INTEGRATION":"1"})
        run("launcher_syntax", ["bash", "-n", "run-local-autohack.sh", "run-complete-autohack.sh", "setup-and-run.sh", "scripts/install-user-service.sh", "scripts/control-user-service.sh", "scripts/node-runtime.sh", "scripts/verify-host.sh", "scripts/configure-hackerone.sh", "scripts/verify-model.sh", "scripts/verify-assessment.sh"])
        if shutil.which("npm") and (ROOT / "node_modules").is_dir():
            run("typescript", ["npx", "--no-install", "tsc", "--noEmit", "--project", "tsconfig.json"], 180)
            run("dashboard_typecheck", ["npx", "--no-install", "tsc", "--noEmit", "--project", "packages/dashboard/tsconfig.json"], 180)
            # All of these tests are local-only and intercept or mock outbound traffic.
            # They never submit to a real platform or contact program assets.
            for test_name, script in [
                ("mock_program_assessment", "scripts/test-mock-assessment.ts"),
                ("authorized_source", "scripts/test-authorized-source.ts"),
                ("program_selection", "scripts/test-program-selection.ts"),
                ("discovery_feeds", "scripts/test-discovery-feeds.ts"),
                ("provider_preflight", "scripts/test-provider-preflight.ts"),
                ("earnings", "scripts/test-earnings.ts"),
                ("explicit_scope", "scripts/test-scope.ts"),
                ("daily_hunt_quota", "scripts/test-daily-quota.ts"),
                ("submission_recovery", "scripts/test-submission-outbox.ts"),
                ("mock_provider_serializer", "scripts/test-mock-submission.ts"),
                ("bounded_http", "scripts/test-scoped-http.ts"),
                ("offline_end_to_end_fixture", "scripts/test-offline-end-to-end.ts"),
            ]:
                run(test_name, ["node", "--import", "tsx", script], 180)

            # Compile/load the actual native addon and exercise the real database
            # and dashboard with a temporary schema. Never touch the operator DB.
            with tempfile.TemporaryDirectory(prefix="autohack-acceptance-") as temp:
                env = {**os.environ, "GITHUB_TOKEN": "offline-acceptance-fixture",
                       "DB_PATH": str(Path(temp) / "fixture.sqlite"),
                       "CI_SQLITE_INTEGRATION": "1", "CI_DASHBOARD_SMOKE": "1"}
                run("native_schema", ["npm", "run", "db:push"], 180, env)
                if RESULTS["native_schema"]["passed"]:
                    run("static_lead_queue", ["node", "--import", "tsx", "scripts/test-static-lead-queue.ts"], 180, env)
                    run("hunt_failure", ["node", "--import", "tsx", "scripts/test-hunt-failure.ts"], 180, env)
                    run("progress_diagnostic", ["node", "--import", "tsx", "scripts/test-progress-diagnostic.ts"], 180, env)
                    run("database_initialization", ["node", "--import", "tsx", "scripts/test-db-initialization.ts"], 180, env)
                    run("native_sqlite_dashboard", ["node", "--import", "tsx", "scripts/test-sqlite-pipeline.ts"], 180, env)
                    run("service_restart", [sys.executable, "scripts/test-service-restart.py"], 240, env)

        else:
            record("typescript", False, "Local Node dependencies not installed")
        if args.offline:
            return emit(args, "offline_regression")
    try:
        settings = runtime_settings()
        record("runtime_settings", True, "Runtime settings loaded; deterministic engine required")
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        record("runtime_settings", False, "Runtime settings unavailable; install Node dependencies")
        return emit(args, "host_acceptance")
    if not shutil.which("npx"):
        record("deterministic_controller", False, "npx is required for the local controller regression")
    else:
        run("deterministic_controller",
            ["node", "--import", "tsx", "scripts/test-deterministic-lotus.ts"], 240,
            env={**os.environ, "LOCAL_MODEL_ADAPTER":"deterministic",
                 "AUTOHACK_OLLAMA_URL":"http://127.0.0.1:1/api/chat"})
        run("deterministic_inventory",
            ["node", "--import", "tsx", "scripts/test-deterministic-full-inventory.ts"], 240,
            env={**os.environ, "LOCAL_MODEL_ADAPTER":"deterministic",
                 "AUTOHACK_OLLAMA_URL":"http://127.0.0.1:1/api/chat"})
    if args.model_only:
        return emit(args, "deterministic_acceptance")
    # Confirm the live solver retains the submission boundary for static leads.
    solver_source = (ROOT / "packages/security-solver/src/index.ts").read_text()
    record("offline_submission_boundary",
           '!finding.id.startsWith("offline-")' in solver_source,
           "Offline static leads excluded from unattended external submission"
           if '!finding.id.startsWith("offline-")' in solver_source
           else "Offline submission boundary missing")
    path = Path(settings["dbPath"]).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    if path.is_file():
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3)
            try:
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                record("database_schema", {"security_findings", "security_programs"} <= tables,
                       "Tables: " + ", ".join(sorted(tables & {"security_findings", "security_programs"})))
            finally:
                conn.close()
        except sqlite3.Error as exc:
            record("database_schema", False, str(exc))
    else:
        record("database_schema", False, "Database not initialized")
    record("runtime_config", (ROOT / ".env").is_file(), "Local .env present" if (ROOT / ".env").is_file() else "Local .env absent")
    if args.provider:
        run("hackerone_authenticated_read", ["node", "--import", "tsx", "scripts/provider-preflight.ts"], 25)
    return emit(args, "host_acceptance")

if __name__ == "__main__":
    raise SystemExit(main())
