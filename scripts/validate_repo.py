#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ERRORS: list[str] = []
GENERATED_DIRS = {".git", ".next", "node_modules", "target"}
MIGRATION_NAME = re.compile(r"^(?P<version>\d+)_[a-z0-9][a-z0-9_]*\.sql$")


def fail(message: str) -> None:
    ERRORS.append(message)


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(path: str) -> None:
    if not (ROOT / path).exists():
        fail(f"missing required path: {path}")


def is_generated(path: pathlib.Path) -> bool:
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        return True
    return any(part in GENERATED_DIRS for part in relative.parts)


for required in [
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "pnpm-workspace.yaml",
    "pnpm-lock.yaml",
    ".node-version",
    "rust-toolchain.toml",
    "apps/backend/Cargo.toml",
    "apps/site-runtime/Cargo.toml",
    "apps/frontend/package.json",
    "crates/domain/Cargo.toml",
    "crates/executor-core/Cargo.toml",
    "docs/architecture.md",
    "docs/toolchain.yaml",
    "migrations/0001_foundation.sql",
    "migrations/0009_inventory_lifecycle.sql",
]:
    require(required)

for forbidden in ROOT.rglob("*"):
    if is_generated(forbidden):
        continue
    if forbidden.is_file() and forbidden.name in {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
    }:
        fail(f"forbidden competing lockfile: {forbidden.relative_to(ROOT)}")

package = json.loads(text("package.json"))
if package.get("packageManager") != "pnpm@11.21.0":
    fail("root packageManager must be exactly pnpm@11.21.0")
if package.get("engines", {}).get("node") != text(".node-version").strip():
    fail("Node pin differs between package.json engines and .node-version")

frontend = json.loads(text("apps/frontend/package.json"))
react = frontend.get("dependencies", {}).get("react")
react_dom = frontend.get("dependencies", {}).get("react-dom")
if react != react_dom:
    fail("react and react-dom must use the exact same patch")

executor_tree = "\n".join(
    p.read_text(encoding="utf-8", errors="ignore")
    for p in (ROOT / "crates/executor-core").rglob("*")
    if p.is_file() and not is_generated(p)
)
for forbidden_symbol in ["tauri", "next", "axum", "sqlx", "postgres"]:
    if re.search(rf"\b{re.escape(forbidden_symbol)}\b", executor_tree, re.IGNORECASE):
        fail(f"executor-core must not depend on {forbidden_symbol}")

backend_tree = "\n".join(
    p.read_text(encoding="utf-8", errors="ignore")
    for p in (ROOT / "apps/backend/src").rglob("*.rs")
)
for forbidden_symbol in ["TcpStream::connect", "snmp", "winrm", "ssh2"]:
    if forbidden_symbol.lower() in backend_tree.lower():
        fail(f"backend contains direct network execution marker: {forbidden_symbol}")

compose = text("docker-compose.yml")
if "privileged: true" in compose:
    fail("privileged: true is forbidden")
if re.search(r"image:\s*[^\n]*:latest\b", compose):
    fail("Docker image tag latest is forbidden")

runtime_source = text("apps/site-runtime/src/main.rs")
if '"127.0.0.1:9765"' not in runtime_source:
    fail("runtime default bind must remain loopback")

migration = text("migrations/0001_foundation.sql")
for token in ["routing_domains", "cidr", "inet", "outbox_events", "audit_events"]:
    if token not in migration:
        fail(f"foundation migration is missing {token}")

migration_versions: dict[int, list[str]] = {}
migrations_dir = ROOT / "migrations"
for migration_path in sorted(migrations_dir.glob("*.sql")):
    match = MIGRATION_NAME.fullmatch(migration_path.name)
    if match is None:
        fail(
            "migration filename must be '<numeric-version>_<snake_case_name>.sql': "
            f"{migration_path.name}"
        )
        continue
    version = int(match.group("version"))
    migration_versions.setdefault(version, []).append(migration_path.name)

for version, names in sorted(migration_versions.items()):
    if len(names) > 1:
        fail(f"duplicate migration version {version}: {', '.join(names)}")

if ERRORS:
    for error in ERRORS:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("repository structural validation: OK")
