#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

PATH = Path("docs/roadmap.json")
PHASE_ORDER = {"roadmap": -1, "foundation": 0, "mvp": 1, "v1": 2, "v2": 3, "cross-cutting": 4, "release": 5}
CYCLE_ORDER = {"roadmap": -1, "continuous": -1, **{f"C{index}": index for index in range(14)}, "release-trial": 14}


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    if not PATH.exists():
        fail("docs/roadmap.json is missing; run scripts/sync_roadmap.py")
    data = json.loads(PATH.read_text(encoding="utf-8"))
    issues = data.get("issues", [])
    by_number = {int(item["issue"]): item for item in issues}
    if len(by_number) != len(issues):
        fail("roadmap contains duplicate issue classification")

    controlled = set(range(1, 119))
    present = controlled & set(by_number)
    if present != controlled:
        fail(f"controlled roadmap mismatch; missing={sorted(controlled-present)} extra={sorted(present-controlled)}")
    if 119 not in by_number:
        fail("release extension #119 must be represented")

    expected_counts = {"roadmap": 1, "foundation": 19, "mvp": 21, "v1": 46, "v2": 22, "cross-cutting": 9}
    for phase, expected in expected_counts.items():
        actual = sum(1 for number, item in by_number.items() if number <= 118 and item["phase"] == phase)
        if actual != expected:
            fail(f"phase {phase} expected {expected}, got {actual}")

    gates = {item.get("gate"): number for number, item in by_number.items() if item.get("gate")}
    if gates != {"mvp": 31, "v1": 44, "v2": 54}:
        fail(f"invalid gate set: {gates}")
    if by_number[118]["requiredForRelease"]:
        fail("#118 must remain optional")
    if by_number[118]["componentRole"] != "desktop-ui":
        fail("#118 must remain desktop-ui")
    if by_number[117]["componentRole"] != "site-runtime" or not by_number[117]["headlessRequired"]:
        fail("#117 must remain a headless site runtime")
    if by_number[117]["runtimePlacement"] != "site-local":
        fail("#117 must remain site-local")

    graph: dict[int, list[int]] = {}
    for number, item in by_number.items():
        deps = [int(dep) for dep in item.get("hardDependencies", [])]
        graph[number] = deps
        if number in deps:
            fail(f"#{number} has self dependency")
        for dep in deps:
            if dep not in by_number:
                fail(f"#{number} references missing dependency #{dep}")
            dep_item = by_number[dep]
            if number <= 118 and item["phase"] in {"foundation", "mvp", "v1", "v2"} and dep_item["phase"] in {"foundation", "mvp", "v1", "v2"}:
                if PHASE_ORDER[dep_item["phase"]] > PHASE_ORDER[item["phase"]]:
                    fail(f"phase inversion #{number} -> #{dep}")
            cycle = CYCLE_ORDER.get(item["executionCycle"])
            dep_cycle = CYCLE_ORDER.get(dep_item["executionCycle"])
            if cycle is not None and dep_cycle is not None and cycle >= 0 and dep_cycle > cycle:
                fail(f"cycle inversion #{number} ({item['executionCycle']}) -> #{dep} ({dep_item['executionCycle']})")
            if item.get("requiredForRelease") and dep_item.get("phase") in {"foundation", "mvp", "v1", "v2"} and not dep_item.get("requiredForRelease"):
                fail(f"required issue #{number} hard-depends on optional issue #{dep}")

        if item.get("requiresLanReachability") and item.get("runtimePlacement") not in {"site-local", "either"}:
            fail(f"LAN-dependent issue #{number} has invalid placement")
        if item.get("requiresL2Adjacency") and item.get("runtimePlacement") != "site-local":
            fail(f"L2-dependent issue #{number} must be site-local")
        if item.get("refinementStatus") == "ready":
            if item.get("effort") in {"TBD", "XL"} or item.get("uncertainty") == "TBD":
                fail(f"ready issue #{number} has invalid refinement metadata")
            if not item.get("acceptanceCriteriaPresent"):
                fail(f"ready issue #{number} has no acceptance criteria")

    visiting: set[int] = set()
    visited: set[int] = set()

    def walk(node: int) -> None:
        if node in visited:
            return
        if node in visiting:
            fail(f"dependency cycle detected at #{node}")
        visiting.add(node)
        for dep in graph[node]:
            walk(dep)
        visiting.remove(node)
        visited.add(node)

    for number in sorted(graph):
        walk(number)

    if 117 not in graph[75]:
        fail("#75 must hard-depend on #117")
    if 46 in graph[75]:
        fail("#75 must not hard-depend on #46 merely for remote runtime topology")

    print(f"roadmap ok: {len(issues)} issues, dependency graph acyclic")


if __name__ == "__main__":
    main()
