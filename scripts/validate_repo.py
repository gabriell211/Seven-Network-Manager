#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ERRORS: list[str] = []


def fail(message: str) -> None:
    ERRORS.append(message)


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(path: str) -> None:
    if not (ROOT / path).exists():
        fail(f"missing required path: {path}")


for required in [
    "Cargo.toml",
    "package.json",
    "pnpm-workspace.yaml",
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
]:
    require(required)

for forbidden in ROOT.rglob("*"):
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
    if p.is_file()
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

if ERRORS:
    for error in ERRORS:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("repository structural validation: OK")
