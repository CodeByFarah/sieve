"""PR check runs: render the policy evaluation of a pull-request scan and publish it."""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from sieve.core.config import Settings
from sieve.db.models import GitHubInstallation, PullRequestCheck, Repository
from sieve.github.app import GitHubApp

CHECK_NAME = "Sieve"
MAX_LISTED = 10


def _entry(item: dict[str, Any]) -> list[str]:
    version = f" {item['version']}" if item.get("version") else ""
    lines = [
        f"#### {item['advisory']} — {item['package']}{version} ({item['severity']})",
        f"Policy rule: {item['rule']}" if item.get("rule") else "",
        f"Reachability: **{item['verdict']}**" + (" · CISA KEV" if item.get("kev") else ""),
    ]
    if item.get("path"):
        lines.append("```")
        lines.extend(
            f"{'    ' * i}{'↓ ' if i else ''}{step}" for i, step in enumerate(item["path"])
        )
        lines.append("```")
    return [line for line in lines if line]


def render(
    summary: dict[str, Any], settings: Settings, repository: Repository
) -> tuple[str, str, str]:
    """(conclusion, title, markdown text) for the GitHub check run."""
    conclusion = str(summary.get("conclusion", "neutral"))
    blocking = summary.get("blocking", [])
    warnings = summary.get("warnings", [])
    if conclusion == "failure":
        noun = "vulnerability" if len(blocking) == 1 else "vulnerabilities"
        title = f"{len(blocking)} newly reachable {noun} blocked by policy"
    elif conclusion == "neutral":
        title = (
            f"{len(warnings)} finding{'s' if len(warnings) != 1 else ''} to review; nothing blocked"
        )
    else:
        title = "Sieve found no newly reachable vulnerabilities"

    lines = [
        f"Policy version {summary.get('policy_version')} · "
        f"analysed {summary.get('analysed', 0)} dependency findings "
        f"· {summary.get('introduced_count', 0)} new or newly reachable in this pull request",
        "",
    ]
    for heading, items in (("Blocking", blocking), ("Warnings", warnings)):
        if items:
            lines.append(f"### {heading}")
            for item in items[:MAX_LISTED]:
                lines.extend(_entry(item))
            if len(items) > MAX_LISTED:
                lines.append(f"…and {len(items) - MAX_LISTED} more.")
    lines.append("")
    lines.append(f"[Open in Sieve]({settings.public_web_url}/app/repositories/{repository.id})")
    return conclusion, title, "\n".join(lines)


def publish(session: Session, app: GitHubApp, settings: Settings, check_id: uuid.UUID) -> None:
    check = session.get(PullRequestCheck, check_id)
    if check is None:
        return
    repository = session.get(Repository, check.repository_id)
    installation = (
        session.get(GitHubInstallation, repository.installation_id) if repository else None
    )
    if repository is None or installation is None:
        return
    conclusion, title, text = render(check.summary, settings, repository)
    body = {
        "name": CHECK_NAME,
        "head_sha": check.head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {"title": title, "summary": text[:65_000]},
    }
    path = f"/repos/{repository.full_name}"
    if check.github_check_run_id:
        app.as_installation(
            installation.github_installation_id,
            "PATCH",
            f"{path}/check-runs/{check.github_check_run_id}",
            json=body,
        )
    else:
        created = app.as_installation(
            installation.github_installation_id, "POST", f"{path}/check-runs", json=body
        )
        check.github_check_run_id = int(created["id"])
    check.conclusion = conclusion
