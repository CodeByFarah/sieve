"""CISA Known Exploited Vulnerabilities and FIRST EPSS feeds."""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Any

import httpx

from sieve.core.http import get_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    date_added: date
    due_date: date | None
    known_ransomware_use: bool
    vendor: str
    product: str


@dataclass(frozen=True)
class EpssRecord:
    cve_id: str
    score: Decimal
    percentile: Decimal
    score_date: date


def parse_kev(document: Mapping[str, Any]) -> list[KevRecord]:
    records = []
    for entry in document.get("vulnerabilities", []):
        cve = entry.get("cveID", "")
        if not _CVE.match(cve):
            continue
        due = entry.get("dueDate")
        records.append(
            KevRecord(
                cve_id=cve,
                date_added=date.fromisoformat(entry["dateAdded"]),
                due_date=date.fromisoformat(due) if due else None,
                known_ransomware_use=entry.get("knownRansomwareCampaignUse") == "Known",
                vendor=str(entry.get("vendorProject", ""))[:255],
                product=str(entry.get("product", ""))[:255],
            )
        )
    return records


def parse_epss(document: Mapping[str, Any]) -> list[EpssRecord]:
    return [
        EpssRecord(
            cve_id=entry["cve"],
            score=Decimal(entry["epss"]),
            percentile=Decimal(entry["percentile"]),
            score_date=date.fromisoformat(entry["date"]),
        )
        for entry in document.get("data", [])
        if _CVE.match(entry.get("cve", ""))
    ]


def fetch_kev(client: httpx.Client) -> list[KevRecord]:
    document = get_json(client, KEV_URL)
    assert isinstance(document, dict)  # noqa: S101 - narrowed for the type checker
    return parse_kev(document)


def fetch_epss(client: httpx.Client, cve_ids: Iterable[str]) -> list[EpssRecord]:
    """EPSS scores for the given CVEs (the API accepts up to 100 per request)."""
    wanted = sorted({cve for cve in cve_ids if _CVE.match(cve)})
    records: list[EpssRecord] = []
    for start in range(0, len(wanted), EPSS_BATCH):
        batch = wanted[start : start + EPSS_BATCH]
        document = get_json(client, EPSS_URL, params={"cve": ",".join(batch)})
        assert isinstance(document, dict)  # noqa: S101
        records.extend(parse_epss(document))
    return records
