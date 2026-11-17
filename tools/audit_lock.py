#!/usr/bin/env python3
"""Offline check of Cargo.lock against a clone of the RustSec advisory database.

    git clone --depth 1 https://github.com/rustsec/advisory-db
    python3 tools/audit_lock.py Cargo.lock advisory-db

Reports every advisory (vulnerability, unsound, unmaintained, notice) whose
affected range contains a locked crate version. Exit code 1 if any applies.

Cargo.lock also lists crates that only other platforms would build (for
example the Linux GTK libraries of the window toolkit, which CIPHERIS does
not use on Linux). To check only what the shipped builds contain, pass the
output of `cargo metadata --filter-platform <target>` for every release
target; then only crates that one of these builds resolves are checked:

    python3 tools/audit_lock.py Cargo.lock advisory-db meta-*.json
CI runs `cargo deny` for the same purpose; this script is a dependency free
second opinion.
"""
import json
import os
import re
import sys
import tomllib


def parse_version(v):
    v = v.split("+")[0]
    core, _, pre = v.partition("-")
    parts = [int(x) for x in core.split(".")] + [0, 0, 0]
    return (parts[0], parts[1], parts[2], 0 if pre else 1, pre)


def matches(version, req):
    """Semver requirement as used by RustSec: comma separated comparators."""
    v = parse_version(version)
    for comp in [c.strip() for c in req.split(",") if c.strip()]:
        m = re.match(r"^(>=|<=|>|<|=|\^|~)?\s*(.+)$", comp)
        op, target = m.group(1) or "^", m.group(2).strip()
        t = parse_version(target)
        if op == ">=" and not v >= t:
            return False
        if op == ">" and not v > t:
            return False
        if op == "<=" and not v <= t:
            return False
        if op == "<" and not v < t:
            return False
        if op == "=" and v[:3] != t[:3]:
            return False
        if op == "~":
            if not (v >= t and v[:2] == t[:2]):
                return False
        if op == "^":
            if v < t:
                return False
            if t[0] > 0 and v[0] != t[0]:
                return False
            if t[0] == 0 and t[1] > 0 and v[:2] != t[:2]:
                return False
            if t[0] == 0 and t[1] == 0 and v[:3] != t[:3]:
                return False
    return True


def advisory_meta(path):
    text = open(path, encoding="utf-8").read()
    m = re.search(r"```toml\n(.*?)\n```", text, re.S)
    if not m:
        return None
    meta = tomllib.loads(m.group(1))
    title = re.search(r"^# (.+)$", text, re.M)
    meta.setdefault("advisory", {})["title"] = title.group(1) if title else ""
    return meta


def main():
    lock_path, db, metadata_paths = sys.argv[1], sys.argv[2], sys.argv[3:]
    lock = tomllib.loads(open(lock_path, encoding="utf-8").read())
    packages = [(p["name"], p["version"]) for p in lock["package"] if "source" in p]
    if metadata_paths:
        built = set()
        for path in metadata_paths:
            meta = json.load(open(path, encoding="utf-8"))
            ids = {node["id"] for node in meta["resolve"]["nodes"]}
            built |= {(p["name"], p["version"]) for p in meta["packages"] if p["id"] in ids}
        skipped = len(packages)
        packages = [p for p in packages if p in built]
        skipped -= len(packages)
        print(f"{skipped} locked crates are built for none of the given targets and were skipped")
    hits = []
    for name, version in packages:
        folder = os.path.join(db, "crates", name)
        if not os.path.isdir(folder):
            continue
        for f in sorted(os.listdir(folder)):
            meta = advisory_meta(os.path.join(folder, f))
            if not meta:
                continue
            adv = meta.get("advisory", {})
            if adv.get("withdrawn"):
                continue
            vers = meta.get("versions", {})
            safe = vers.get("patched", []) + vers.get("unaffected", [])
            if any(matches(version, r) for r in safe):
                continue
            hits.append((name, version, adv.get("id"), adv.get("informational", "vulnerability"), adv.get("title")))
    print(f"checked {len(packages)} locked crates against {db}")
    for h in hits:
        print("ADVISORY", *h)
    if not hits:
        print("no advisory applies to any locked version")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
