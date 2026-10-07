"""Record the advisory data the public demo scans against.

    python -m sieve.demo.snapshot <demo-app-dir> <snapshot-dir>

Queries OSV for every pinned dependency of the demo application, saves each advisory record, and
saves the CISA KEV entries and EPSS scores for the CVEs involved. The snapshot is committed so the
demo is reproducible and does not depend on third-party availability; ``manifest.json`` records
when it was fetched, and the UI shows that date.
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from sieve.advisories.feeds import EPSS_URL, KEV_URL
from sieve.advisories.osv import parse_osv
from sieve.core.http import build_client, get_json, post_json
from sieve.core.workspace import Workspace
from sieve.sbom.inventory import build_inventory

OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"


def _dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_snapshot(app_dir: Path, out_dir: Path, client: httpx.Client) -> dict[str, Any]:
    pinned = [d for d in build_inventory(Workspace(app_dir)).dependencies if d.version]
    queries = [
        {"package": {"name": d.name, "ecosystem": "PyPI"}, "version": d.version} for d in pinned
    ]
    response = post_json(client, OSV_QUERY_BATCH, {"queries": queries})
    assert isinstance(response, dict)  # noqa: S101
    ids = sorted({vuln["id"] for result in response["results"] for vuln in result.get("vulns", [])})

    cves: set[str] = set()
    for advisory_id in ids:
        record = get_json(client, OSV_VULN.format(id=advisory_id))
        assert isinstance(record, dict)  # noqa: S101
        _dump(out_dir / "osv" / f"{advisory_id}.json", record)
        cves.update(parse_osv(record).cve_ids)

    kev = get_json(client, KEV_URL)
    assert isinstance(kev, dict)  # noqa: S101
    kev_entries = [entry for entry in kev.get("vulnerabilities", []) if entry.get("cveID") in cves]
    _dump(out_dir / "kev.json", {"vulnerabilities": kev_entries})

    epss_rows: list[Any] = []
    wanted = sorted(cves)
    for start in range(0, len(wanted), 100):
        page = get_json(client, EPSS_URL, params={"cve": ",".join(wanted[start : start + 100])})
        assert isinstance(page, dict)  # noqa: S101
        epss_rows.extend(page.get("data", []))
    _dump(out_dir / "epss.json", {"data": epss_rows})

    manifest = {
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sources": {"osv": OSV_QUERY_BATCH, "kev": KEV_URL, "epss": EPSS_URL},
        "dependencies": [f"{d.name}=={d.version}" for d in pinned],
        "advisories": len(ids),
        "cves": len(cves),
        "kev_matches": len(kev_entries),
        "epss_scores": len(epss_rows),
    }
    _dump(out_dir / "manifest.json", manifest)
    return manifest


def main() -> None:
    app_dir, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    with build_client(timeout=60) as client:
        manifest = build_snapshot(app_dir, out_dir, client)
    print(json.dumps(manifest, indent=2))  # noqa: T201 - CLI output


if __name__ == "__main__":
    main()
