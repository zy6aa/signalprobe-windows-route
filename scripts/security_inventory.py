"""Query OSV's public API for exact Cargo.lock registry versions; findings are data, not a safety PASS."""
import json
from pathlib import Path
import sys
import tomllib
import urllib.request

lock = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
packages = [p for p in lock["package"] if p.get("source", "").startswith("registry+")]
findings = []
for start in range(0, len(packages), 200):
    chunk = packages[start:start + 200]
    payload = {"queries": [{"package": {"name": p["name"], "ecosystem": "crates.io"}, "version": p["version"]} for p in chunk]}
    req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as response:
        results = json.load(response)["results"]
    for package, result in zip(chunk, results, strict=True):
        if result.get("vulns"):
            findings.append({"package": package["name"], "version": package["version"], "advisories": result["vulns"]})
report = {"registry_packages_queried": len(packages), "findings": findings,
          "scope": "OSV registry-version scan; git/path dependencies and reachability not assessed; no security certification"}
Path(sys.argv[2]).write_text(json.dumps(report, indent=2), encoding="utf-8")
print(f"OSV: {len(packages)} registry packages queried, {len(findings)} packages with advisory records. Review report; this is not a safety gate.")
