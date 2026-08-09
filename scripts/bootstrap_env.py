#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path

TARGET = Path(".env")


def token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a local SNM .env with generated secrets")
    parser.add_argument("--force", action="store_true", help="replace an existing .env")
    args = parser.parse_args()
    if TARGET.exists() and not args.force:
        raise SystemExit(".env already exists; use --force only if rotating local development secrets")

    postgres_password = token(24)
    runtime_token = token(48)
    mongo_password = token(24)
    values = {
        "SNM_ENV": "development",
        "SNM_BACKEND_BIND": "127.0.0.1:8080",
        "SNM_RUNTIME_URL": "http://127.0.0.1:9765",
        "SNM_RUNTIME_BIND": "127.0.0.1:9765",
        "SNM_RUNTIME_TOKEN": runtime_token,
        "SNM_RUNTIME_ALLOW_PUBLIC_TARGETS": "false",
        "SNM_RUNTIME_ALLOW_NON_LOOPBACK": "false",
        "SNM_RUN_MIGRATIONS": "true",
        "SNM_DATABASE_MAX_CONNECTIONS": "10",
        "POSTGRES_USER": "snm",
        "POSTGRES_PASSWORD": postgres_password,
        "POSTGRES_DB": "snm",
        "DATABASE_URL": f"postgres://snm:{postgres_password}@127.0.0.1:5432/snm",
        "REDIS_URL": "redis://127.0.0.1:6379/0",
        "SNM_API_BASE_URL": "http://127.0.0.1:8080",
        "MONGO_INITDB_ROOT_USERNAME": "snm",
        "MONGO_INITDB_ROOT_PASSWORD": mongo_password,
    }
    payload = "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"
    TARGET.write_text(payload, encoding="utf-8")
    try:
        os.chmod(TARGET, 0o600)
    except OSError:
        pass
    print("created .env with generated local-only credentials")


if __name__ == "__main__":
    main()
