#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import io
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data/oui/ieee.csv"
METADATA = ROOT / "data/oui/metadata.json"
SOURCES = (
    ("MA-L", 24, "https://standards-oui.ieee.org/oui/oui.csv"),
    ("MA-M", 28, "https://standards-oui.ieee.org/oui28/mam.csv"),
    ("MA-S", 36, "https://standards-oui.ieee.org/oui36/oui36.csv"),
)


def download(url: str) -> tuple[bytes, str | None]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Seven-Network-Manager/1.0 IEEE-OUI-Snapshot"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(), response.headers.get("ETag")


def normalize_assignment(value: str) -> str:
    compact = "".join(ch for ch in value.upper() if ch in "0123456789ABCDEF")
    if not compact:
        raise ValueError("empty assignment")
    return compact


def main() -> int:
    rows: dict[tuple[int, str], tuple[str, str]] = {}
    metadata_sources = []
    for registry, bits, url in SOURCES:
        payload, etag = download(url)
        digest = hashlib.sha256(payload).hexdigest()
        text = payload.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "Assignment" not in reader.fieldnames:
            raise RuntimeError(f"IEEE source {url} has unexpected schema")
        organization_field = (
            "Organization Name"
            if "Organization Name" in reader.fieldnames
            else "OrganizationName"
        )
        if organization_field not in reader.fieldnames:
            raise RuntimeError(f"IEEE source {url} is missing organization name")
        for item in reader:
            assignment = normalize_assignment(item.get("Assignment", ""))
            organization = (item.get(organization_field) or "").strip()
            if not organization:
                continue
            rows[(bits, assignment)] = (organization, registry)
        metadata_sources.append(
            {
                "registry": registry,
                "bits": bits,
                "url": url,
                "sha256": digest,
                "etag": etag,
            }
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["prefix", "bits", "organization", "registry"])
        for (bits, prefix), (organization, registry) in sorted(
            rows.items(), key=lambda item: (item[0][0], item[0][1])
        ):
            writer.writerow([prefix, bits, organization, registry])

    METADATA.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "recordCount": len(rows),
                "sources": metadata_sources,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(rows)} IEEE assignments to {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
