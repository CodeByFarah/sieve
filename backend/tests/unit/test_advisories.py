import json
from decimal import Decimal
from pathlib import Path

import pytest

from sieve.advisories.feeds import parse_epss, parse_kev
from sieve.advisories.osv import fix_commits, parse_osv, preference
from sieve.advisories.versions import Affectedness, constraint_may_be_affected, version_affected
from sieve.db.enums import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures" / "osv"


def load(name: str) -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES / f"{name}.json").read_text())
    return data


RANGE = [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.5.2"}]}]
TWO_RANGES = [
    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]},
    {"type": "ECOSYSTEM", "events": [{"introduced": "3.0"}, {"last_affected": "3.1"}]},
]


@pytest.mark.parametrize(
    ("version", "ranges", "expected"),
    [
        ("0.9", RANGE, Affectedness.NOT_AFFECTED),
        ("1.0", RANGE, Affectedness.AFFECTED),
        ("1.5.1", RANGE, Affectedness.AFFECTED),
        ("1.5.2", RANGE, Affectedness.NOT_AFFECTED),
        ("1.5.2rc1", RANGE, Affectedness.AFFECTED),  # pre-release sorts before the fix
        ("1.10", RANGE, Affectedness.NOT_AFFECTED),  # PEP 440, not string, ordering
        ("1.5.1.post1", RANGE, Affectedness.AFFECTED),
        ("0.0.1", TWO_RANGES, Affectedness.AFFECTED),
        ("2.5", TWO_RANGES, Affectedness.NOT_AFFECTED),
        ("3.1", TWO_RANGES, Affectedness.AFFECTED),  # last_affected is inclusive
        ("3.1.1", TWO_RANGES, Affectedness.NOT_AFFECTED),
        ("not-a-version", RANGE, Affectedness.UNKNOWN),
    ],
)
def test_osv_ecosystem_range_semantics(
    version: str, ranges: list[dict[str, object]], expected: Affectedness
) -> None:
    assert version_affected(version, ranges, []) is expected


def test_explicit_versions_list_is_authoritative() -> None:
    assert version_affected("5.3", [], ["5.3", "5.3.1"]) is Affectedness.AFFECTED
    assert version_affected("5.3.0", [], ["5.3"]) is Affectedness.AFFECTED  # PEP 440 equality
    assert version_affected("5.4", [], ["5.3"]) is Affectedness.NOT_AFFECTED


def test_git_ranges_are_ignored() -> None:
    ranges = [{"type": "GIT", "events": [{"introduced": "abc"}]}]
    assert version_affected("1.0", ranges, []) is Affectedness.NOT_AFFECTED


@pytest.mark.parametrize(
    ("constraint", "expected"), [(">=5.4", False), ("<5.4", True), (None, True), ("~=5.3.0", True)]
)
def test_unpinned_constraints(constraint: str | None, expected: bool) -> None:
    assert constraint_may_be_affected(constraint, [], ["5.1", "5.3.1"]) is expected


class TestOsvParsing:
    def test_real_ghsa_record(self) -> None:
        advisory = parse_osv(load("GHSA-8q59-q68h-6hv4"))
        assert advisory.source_id == "GHSA-8q59-q68h-6hv4"
        assert advisory.cve_ids == ["CVE-2020-14343"]
        assert advisory.severity is Severity.CRITICAL
        assert advisory.cvss_vector is not None
        assert advisory.cvss_vector.startswith("CVSS:3")
        assert advisory.cvss_score == Decimal("9.8")
        assert [a.name for a in advisory.affected] == ["pyyaml"]
        assert (
            version_affected("5.3", advisory.affected[0].ranges, advisory.affected[0].versions)
            is Affectedness.AFFECTED
        )
        assert (
            version_affected("5.4", advisory.affected[0].ranges, advisory.affected[0].versions)
            is Affectedness.NOT_AFFECTED
        )

    def test_record_without_cvss_has_unknown_severity(self) -> None:
        advisory = parse_osv(load("PYSEC-2021-142"))
        assert advisory.severity is Severity.UNKNOWN
        assert advisory.cvss_score is None

    def test_content_hash_is_stable_and_sensitive(self) -> None:
        record = load("GHSA-x84v-xcm2-53pg")
        assert parse_osv(record).content_hash == parse_osv(dict(record)).content_hash
        assert (
            parse_osv({**record, "summary": "changed"}).content_hash
            != parse_osv(record).content_hash
        )

    def test_oversized_and_unsafe_fields_are_capped(self) -> None:
        record = {
            **load("GHSA-x84v-xcm2-53pg"),
            "details": "x" * 50_000,
            "references": [
                {"type": "WEB", "url": "javascript:alert(1)"},
                {"type": "WEB", "url": "http://plain"},
            ],
        }
        advisory = parse_osv(record)
        assert advisory.details is not None
        assert len(advisory.details) == 20_000
        assert advisory.references == []

    def test_missing_required_fields_raise(self) -> None:
        with pytest.raises(KeyError):
            parse_osv({"id": "X"})

    def test_ecosystem_specific_symbols(self) -> None:
        record = {
            "id": "TEST-1",
            "modified": "2024-01-01T00:00:00Z",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "Demo_Pkg"},
                    "ecosystem_specific": {"imports": [{"path": "demo.mod", "symbols": ["load"]}]},
                },
                {"package": {"ecosystem": "npm", "name": "other"}},
            ],
        }
        advisory = parse_osv(record)
        assert [(a.name, a.symbols) for a in advisory.affected] == [("demo-pkg", ["demo.mod.load"])]


def test_repeated_package_entries_are_merged() -> None:
    record = {
        "id": "TEST-2",
        "modified": "2024-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "urllib3"},
                "versions": ["1.0"],
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.18"}]}
                ],
            },
            {
                "package": {"ecosystem": "PyPI", "name": "URLLIB3"},
                "versions": ["2.0.0"],
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.0.7"}]}
                ],
            },
        ],
    }
    (affected,) = parse_osv(record).affected
    assert affected.versions == ["1.0", "2.0.0"]
    assert len(affected.ranges) == 2
    assert version_affected("2.0.5", affected.ranges, []) is Affectedness.AFFECTED


def test_fix_commit_extraction_only_accepts_github_commit_urls() -> None:
    commits = fix_commits(
        [
            {
                "type": "FIX",
                "url": "https://github.com/yaml/pyyaml/commit/a001f2782501ad2d24986959f0239a354675f9dc",
            },
            {"type": "FIX", "url": "https://evil.example/commit/abc"},
            {"type": "WEB", "url": "https://github.com/yaml/pyyaml/pull/472"},
        ]
    )
    assert [(c.owner, c.repo, c.sha[:7]) for c in commits] == [("yaml", "pyyaml", "a001f27")]


def test_ghsa_preferred_over_pysec() -> None:
    assert sorted(["PYSEC-2021-142", "GHSA-8q59-q68h-6hv4", "OSV-1"], key=preference)[0].startswith(
        "GHSA"
    )


def test_kev_and_epss_feed_parsing() -> None:
    kev = parse_kev(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                },
                {"cveID": "not-a-cve", "dateAdded": "2021-12-10"},
            ]
        }
    )
    assert [(k.cve_id, k.known_ransomware_use) for k in kev] == [("CVE-2021-44228", True)]
    epss = parse_epss(
        {
            "data": [
                {
                    "cve": "CVE-2020-14343",
                    "epss": "0.01234",
                    "percentile": "0.85",
                    "date": "2026-10-05",
                }
            ]
        }
    )
    assert epss[0].score == Decimal("0.01234")
