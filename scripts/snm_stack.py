#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"
BASE_COMPOSE = ROOT / "docker-compose.yml"
L2_COMPOSE = ROOT / "docker-compose.l2.yml"
BOOTSTRAP = ROOT / "scripts" / "bootstrap_env.py"


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT, text=True, check=check)


def ensure_env() -> None:
    if ENV_FILE.exists():
        return
    run([sys.executable, str(BOOTSTRAP)])
    if not ENV_FILE.exists():
        raise SystemExit("bootstrap_env.py did not create .env")


def compose_args(args: argparse.Namespace) -> list[str]:
    command = ["docker", "compose", "--env-file", str(ENV_FILE), "-f", str(BASE_COMPOSE)]
    if args.l2:
        if sys.platform != "linux":
            raise SystemExit("--l2 is supported only on Linux")
        command.extend(["-f", str(L2_COMPOSE)])
    for profile in sorted(set(args.profile or [])):
        command.extend(["--profile", profile])
    return command


def validate_tools() -> None:
    run(["docker", "version"], check=True)
    run(["docker", "compose", "version"], check=True)


def command_up(args: argparse.Namespace) -> None:
    ensure_env()
    validate_tools()
    command = compose_args(args)
    run([*command, "config", "--quiet"])
    run([*command, "up", "-d", "--build", "--remove-orphans"])
    command_inspect(args)


def command_down(args: argparse.Namespace) -> None:
    ensure_env()
    validate_tools()
    run([*compose_args(args), "down", "--remove-orphans"])


def command_reset(args: argparse.Namespace) -> None:
    if not args.confirm_reset:
        raise SystemExit(
            "reset destroys PostgreSQL and optional datastore volumes; rerun with --confirm-reset"
        )
    ensure_env()
    validate_tools()
    command = compose_args(args)
    run([*command, "down", "--volumes", "--remove-orphans"])
    if args.regenerate_secrets:
        ENV_FILE.unlink(missing_ok=True)
        run([sys.executable, str(BOOTSTRAP)])
    run([*command, "config", "--quiet"])
    run([*command, "up", "-d", "--build", "--remove-orphans"])
    command_inspect(args)


def command_inspect(args: argparse.Namespace) -> None:
    ensure_env()
    validate_tools()
    command = compose_args(args)
    result = subprocess.run(
        [*command, "ps", "--format", "json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    output = result.stdout.strip()
    if not output:
        print("no stack containers found")
        return

    rows: list[dict[str, object]] = []
    # Docker Compose has emitted both JSON arrays and one-JSON-object-per-line
    # across supported releases. Accept both without depending on a CLI patch.
    try:
        parsed = json.loads(output)
        rows = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in output.splitlines() if line.strip()]

    unhealthy = []
    for row in rows:
        service = str(row.get("Service") or row.get("Name") or "unknown")
        state = str(row.get("State") or "unknown")
        health = str(row.get("Health") or "")
        suffix = f" health={health}" if health else ""
        print(f"{service}: state={state}{suffix}")
        if state.lower() != "running" or health.lower() == "unhealthy":
            unhealthy.append(service)

    if unhealthy:
        raise SystemExit(f"stack has non-ready containers: {', '.join(sorted(unhealthy))}")


def command_logs(args: argparse.Namespace) -> None:
    ensure_env()
    validate_tools()
    command = compose_args(args)
    tail = str(args.tail)
    services = args.service or []
    run([*command, "logs", "--tail", tail, *services])


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Seven Network Manager stack lifecycle")
    result.add_argument(
        "command",
        choices=["up", "down", "reset", "inspect", "logs"],
        help="stack operation",
    )
    result.add_argument(
        "--profile",
        action="append",
        choices=["mongo", "rabbit"],
        help="enable an optional datastore profile; may be repeated",
    )
    result.add_argument(
        "--l2",
        action="store_true",
        help="Linux laboratory mode for L2/ARP runtime access",
    )
    result.add_argument(
        "--confirm-reset",
        action="store_true",
        help="required acknowledgement for destructive reset",
    )
    result.add_argument(
        "--regenerate-secrets",
        action="store_true",
        help="with reset, regenerate local .env secrets",
    )
    result.add_argument("--service", action="append", help="service filter for logs")
    result.add_argument("--tail", type=int, default=200, help="number of log lines")
    return result


def main() -> None:
    args = parser().parse_args()
    if args.tail < 1 or args.tail > 10000:
        raise SystemExit("--tail must be between 1 and 10000")
    handlers = {
        "up": command_up,
        "down": command_down,
        "reset": command_reset,
        "inspect": command_inspect,
        "logs": command_logs,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
