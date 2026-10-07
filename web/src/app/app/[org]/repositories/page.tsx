import Link from "next/link";
import { api, type Repository } from "@/lib/api";
import { EmptyState } from "@/components/ui";
import { relativeTime } from "@/lib/format";

export const dynamic = "force-dynamic";

const HEALTH: Record<string, string> = {
  attention: "text-reach",
  failing: "text-reach",
  pending: "text-muted",
  healthy: "text-clear",
};

export default async function RepositoriesPage({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const repos = await api<Repository[]>(`/api/v1/orgs/${org}/repositories`);
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">Repositories</h1>
      {repos.length === 0 ? (
        <EmptyState title="No repositories connected yet." body="Install the Sieve GitHub App on an account or organization, then choose the repositories to analyse." />
      ) : (
        <ul className="divide-y divide-line">
          {repos.map((repo) => (
            <li key={repo.id} className="grid gap-2 py-4 sm:grid-cols-[1fr_auto] sm:items-baseline">
              <div>
                <Link href={`/app/${org}/repositories/${repo.id}`} className="text-lg font-medium hover:underline">{repo.full_name}</Link>
                <p className="text-sm text-muted">
                  {repo.latest_scan ? `Last scanned ${relativeTime(repo.latest_scan.finished_at ?? repo.latest_scan.created_at)}` : "Not scanned yet"} · {repo.default_branch}
                </p>
              </div>
              <div className="text-sm">
                <span className="tabular-nums">{repo.counts.total} vulnerabilities: </span>
                <span className="text-reach">{repo.counts.reachable} reachable</span>, {repo.counts.needs_review} to review, {repo.counts.not_reached} not reached
                <span className={`ml-3 capitalize ${HEALTH[repo.health]}`}>{repo.health}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
