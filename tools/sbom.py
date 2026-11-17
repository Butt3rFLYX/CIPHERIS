#!/usr/bin/env python3
"""Writes a CycloneDX 1.5 software bill of materials for CIPHERIS.

    cargo metadata --format-version 1 --locked > metadata.json
    python3 tools/sbom.py Cargo.lock metadata.json > cipheris-sbom.cdx.json

Every crate in Cargo.lock becomes a component with its version, package URL,
licence (from cargo metadata) and, for crates.io packages, the SHA 256
checksum recorded in the lockfile. No network access, no extra tools.
"""
import json
import sys
import tomllib
import uuid
from datetime import datetime, timezone


def main():
    lock = tomllib.loads(open(sys.argv[1], encoding="utf-8").read())
    meta = json.load(open(sys.argv[2], encoding="utf-8"))
    licences = {(p["name"], p["version"]): p.get("license") for p in meta["packages"]}
    root = next(p for p in meta["packages"] if p["name"] == "cipheris")

    def ref(name, version):
        return f"pkg:cargo/{name}@{version}"

    components = []
    for p in lock["package"]:
        name, version = p["name"], p["version"]
        c = {
            "type": "application" if name == "cipheris" else "library",
            "bom-ref": ref(name, version),
            "name": name,
            "version": version,
            "purl": ref(name, version),
        }
        lic = licences.get((name, version))
        if lic:
            c["licenses"] = [{"expression": lic.replace("/", " OR ")}]
        if "checksum" in p:
            c["hashes"] = [{"alg": "SHA-256", "content": p["checksum"]}]
        if "source" not in p:
            c["scope"] = "required"
        components.append(c)

    deps = []
    for p in lock["package"]:
        out = []
        for d in p.get("dependencies", []):
            parts = d.split(" ")
            if len(parts) > 1:
                out.append(ref(parts[0], parts[1]))
            else:
                v = next(q["version"] for q in lock["package"] if q["name"] == parts[0])
                out.append(ref(parts[0], v))
        deps.append({"ref": ref(p["name"], p["version"]), "dependsOn": sorted(out)})

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "bom-ref": ref("cipheris", root["version"]),
                "name": "cipheris",
                "version": root["version"],
                "licenses": [{"expression": root.get("license") or "MIT"}],
            },
            "tools": {"components": [{"type": "application", "name": "tools/sbom.py"}]},
        },
        "components": [c for c in components if c["name"] != "cipheris"],
        "dependencies": deps,
    }
    json.dump(bom, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
