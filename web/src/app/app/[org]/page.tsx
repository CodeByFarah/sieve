import Link from "next/link";
import { notFound } from "next/navigation";
import { api, ApiError, type FindingPage, type Overview } from "@/lib/api";
import { ExposureMap, type MapItem } from "@/components/exposure-map";
import { FindingTable } from "@/components/finding-table";
import { DemoRunButton } from "@/components/demo-run-button";
import { EmptyState, Panel } from "@/components/ui";
import { relativeTime } from "@/lib/format";

export const dynamic = "force-dynamic";

const ACTIONS: Record<string, string> = {
  "scan.requested": "Scan requested",
  "scan.completed": "Scan completed",
  "scan.failed": "Scan failed",
  "finding.created": "New finding",
  "finding.resolved": "Finding resolved",
  "finding.verdict_changed": "Verdict changed",
  "review.decided": "Review recorded",
  "vex.generated": "VEX generated",
  "policy.changed": "Policy changed",
  "repository.added": "Repository added",
};

export default async function OverviewPage({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  let data: Overview;
  let all: FindingPage;
  try {
    [data, all] = await Promise.all([
      api<Overview>(`/api/v1/orgs/${org}/overview`),
      api<FindingPage>(`/api/v1/orgs/${org}/findings?limit=200`),
    ]);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }
  const t = data.totals;
  const share = (n: number) => (t.total ? `${(n / t.total) * 100}%` : "0%");

  return (
    <div className="space-y-10">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">How exposed are you right now?</h1>
          <p className="mt-1 text-muted">
            {t.total} open vulnerabilities across {data.repositories.length} repositor{data.repositories.length === 1 ? "y" : "ies"}.
          </p>
        </div>
        {data.organization.account_type === "demo" && <DemoRunButton label="Run a fresh scan" />}
      </div>

      {t.total === 0 ? (
        <EmptyState title="No vulnerabilities to show yet." body="Findings appear here after the first scan of a repository completes." />
      ) : (
        <section aria-label="Reachability summary">
          <div className="flex h-3 overflow-hidden rounded-full" role="img"
            aria-label={`${t.reachable} reachable, ${t.needs_review} need review, ${t.not_reached} not reached`}>
            <span className="bg-reach" style={{ width: share(t.reachable) }} />
            <span className="bg-review" style={{ width: share(t.needs_review) }} />
            <span className="bg-clear" style={{ width: share(t.not_reached) }} />
          </div>
          <dl className="mt-4 grid grid-cols-2 gap-6 sm:grid-cols-4">
            {([
              ["Reachable", t.reachable, "text-reach", "reachable"],
              ["Need review", t.needs_review, "text-review", "needs_review"],
              ["Not reached", t.not_reached, "text-clear", "not_reached"],
              ["Known exploited", t.kev, "", null],
            ] as const).map(([label, value, color, verdict]) => (
              <div key={label}>
                <dt className="text-sm text-muted">{label}</dt>
                <dd className={`text-3xl font-semibold tabular-nums ${color}`}>
                  <Link href={verdict ? `/app/${org}/findings?verdict=${verdict}` : `/app/${org}/findings?kev=true`}>{value}</Link>
                </dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      {all.items.length > 0 && (
        <Panel title="Where the risk sits">
          <ExposureMap items={all.items as MapItem[]} org={org} />
        </Panel>
      )}

      {data.top_findings.length > 0 && (
        <Panel title="Fix these first" aside={<Link href={`/app/${org}/findings?verdict=reachable`} className="text-sm text-muted hover:text-text">All reachable</Link>}>
          <FindingTable org={org} items={data.top_findings} />
        </Panel>
      )}

      <div className="grid gap-10 lg:grid-cols-[1.3fr_1fr]">
        <Panel title="Severity against reachability">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-muted"><th className="pb-2 font-normal">Severity</th><th className="pb-2 text-right font-normal">Reachable</th><th className="pb-2 text-right font-normal">Review</th><th className="pb-2 text-right font-normal">Not reached</th></tr></thead>
            <tbody>
              {data.severity.map((row) => (
                <tr key={row.severity} className="border-t border-line/60">
                  <td className="py-2 capitalize">{row.severity}</td>
                  <td className={`py-2 text-right tabular-nums ${row.reachable ? "text-reach" : "text-muted"}`}>{row.reachable}</td>
                  <td className="py-2 text-right tabular-nums">{row.needs_review}</td>
                  <td className="py-2 text-right tabular-nums text-muted">{row.not_reached}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Recent activity" aside={<Link href={`/app/${org}/activity`} className="text-sm text-muted hover:text-text">All activity</Link>}>
          <ol className="space-y-2 text-sm">
            {data.activity.slice(0, 8).map((event) => (
              <li key={event.seq} className="flex justify-between gap-4">
                <span>{ACTIONS[event.action] ?? event.action}{event.actor_login ? ` by ${event.actor_login}` : ""}</span>
                <span className="shrink-0 text-muted">{relativeTime(event.occurred_at)}</span>
              </li>
            ))}
          </ol>
        </Panel>
      </div>

      <Panel title="Repositories">
        <ul className="divide-y divide-line/60">
          {data.repositories.map((repo) => (
            <li key={repo.id} className="flex flex-wrap items-baseline justify-between gap-4 py-3">
              <Link href={`/app/${org}/repositories/${repo.id}`} className="font-medium hover:underline">{repo.full_name}</Link>
              <span className="text-sm text-muted">
                <span className="text-reach">{repo.counts.reachable} reachable</span>, {repo.counts.needs_review} to review and{" "}
                {repo.counts.not_reached} not reached, scanned {relativeTime(repo.latest_scan?.finished_at ?? repo.latest_scan?.created_at)}
              </span>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
