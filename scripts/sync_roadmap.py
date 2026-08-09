#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path

REPO = os.environ.get("GITHUB_REPOSITORY", "gabriell211/Seven-Network-Manager")
TOKEN = os.environ.get("GITHUB_TOKEN")
OUTPUT = Path("docs/roadmap.json")

CYCLES = {
    "C0": [2, 89, 3, 4, 5, 7, 8, 9],
    "C1": [6, 10, 11, 12, 13, 14, 15, 57, 117, 86, 97],
    "C2": [16, 84, 58, 17, 18, 87],
    "C3": [19, 20, 21, 22, 23, 24, 25, 60, 61, 26, 30],
    "C4": [27, 28, 29, 31],
    "C5": [39, 40, 32, 90, 104, 67, 69, 78, 68, 98],
    "C6": [33, 34, 71, 83, 72, 73, 42],
    "C7": [35, 36, 64, 105, 115, 66, 92, 94, 96],
    "C8": [65, 91, 95, 93, 37, 82, 85],
    "C9": [70, 38, 41, 43, 77, 100, 106, 107, 108, 118, 44],
    "C10": [45, 75, 46],
    "C11": [47, 74, 76],
    "C12": [48, 50, 51, 52, 53, 110, 112],
    "C13": [49, 81, 88, 102, 103, 109, 111, 114, 54],
}
CROSS = {55, 56, 59, 79, 80, 99, 101, 113, 116}
GATES = {31: "mvp", 44: "v1", 54: "v2"}
LAN = {
    17, 18, 19, 20, 21, 22, 27, 28, 29, 32, 33, 35, 36, 37, 60, 62, 63,
    64, 65, 66, 67, 69, 70, 72, 73, 74, 75, 76, 78, 82, 83, 85, 87, 88,
    90, 91, 92, 93, 94, 95, 96, 102, 104, 105, 106, 107, 108, 109, 111, 115,
    117,
}
L2 = {18, 35, 36, 64, 92, 94, 96, 102, 105, 115}
SITE_LOCAL = LAN | {117}


def api(path: str):
    url = f"https://api.github.com/repos/{REPO}/{path}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "snm-roadmap-sync"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def fetch_issues() -> dict[int, dict]:
    result: dict[int, dict] = {}
    for page in range(1, 4):
        items = api(f"issues?state=all&per_page=100&page={page}")
        if not items:
            break
        for item in items:
            if "pull_request" in item:
                continue
            number = int(item["number"])
            if 1 <= number <= 119:
                result[number] = item
    return result


def phase_for(number: int, title: str) -> str:
    if number == 1:
        return "roadmap"
    prefix = title.split("]", 1)[0].lstrip("[").lower()
    return {
        "foundation": "foundation",
        "mvp": "mvp",
        "v1.0": "v1",
        "v2.0": "v2",
        "cross-cutting": "cross-cutting",
        "release": "release",
    }.get(prefix, "unknown")


def cycle_for(number: int) -> str:
    if number == 1:
        return "roadmap"
    if number in CROSS:
        return "continuous"
    if number == 119:
        return "release-trial"
    for cycle, numbers in CYCLES.items():
        if number in numbers:
            return cycle
    return "unassigned"


def dependency_section(body: str) -> list[int]:
    match = re.search(r"^## Depend(?:ência|ências)\s*$([\s\S]*?)(?=^## |\Z)", body, re.MULTILINE | re.IGNORECASE)
    if not match:
        return []
    return sorted({int(value) for value in re.findall(r"#(\d+)", match.group(1))})


def effort_for(number: int) -> tuple[str, str, str]:
    cycle = cycle_for(number)
    if cycle in {"C0", "C1"}:
        large = {2, 4, 6, 7, 10, 11, 12, 13, 14, 15, 97, 117}
        return ("L" if number in large else "M", "medium" if number in {6, 10, 11, 97, 117} else "low", "refined")
    if number == 119:
        return ("M", "low", "refined")
    return ("TBD", "TBD", "unrefined")


def component_for(number: int) -> str:
    if number == 117:
        return "site-runtime"
    if number == 118:
        return "desktop-ui"
    if number in {5, 8, 11, 12, 13, 14, 23, 38, 39, 45, 46, 57, 86, 97}:
        return "control-plane"
    if number in LAN:
        return "executor-core"
    return "shared"


def main() -> None:
    issues = fetch_issues()
    missing = [number for number in range(1, 120) if number not in issues]
    if missing:
        raise SystemExit(f"missing issues from GitHub: {missing}")

    entries = []
    for number in range(1, 120):
        issue = issues[number]
        phase = phase_for(number, issue["title"])
        effort, uncertainty, refinement = effort_for(number)
        entries.append({
            "issue": number,
            "title": issue["title"],
            "phase": phase,
            "executionCycle": cycle_for(number),
            "requiredForRelease": phase in {"foundation", "mvp", "v1", "v2"} and number != 118,
            "checkpoint": "continuous" if number in CROSS else None,
            "hardDependencies": dependency_section(issue.get("body") or ""),
            "integrations": [],
            "scalingIntegrations": [],
            "owner": "gabriell211",
            "gate": GATES.get(number),
            "componentRole": component_for(number),
            "runtimePlacement": "site-local" if number in SITE_LOCAL else ("desktop-local" if number == 118 else "control-plane"),
            "deploymentModes": ["development", "lab", "production-mvp-onprem"] if phase in {"foundation", "mvp", "cross-cutting", "release"} else ["development", "lab", "production-central"],
            "requiresLanReachability": number in LAN,
            "requiresL2Adjacency": number in L2,
            "headlessRequired": number == 117,
            "effort": effort,
            "uncertainty": uncertainty,
            "refinementStatus": refinement,
            "acceptanceCriteriaPresent": "## Critérios de aceite" in (issue.get("body") or ""),
        })

    document = {
        "schemaVersion": 1,
        "repository": REPO,
        "controlledRange": {"roadmap": [1, 118], "releaseExtensions": [119]},
        "owner": "gabriell211",
        "issues": entries,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
