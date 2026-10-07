import Link from "next/link";
import { api, type FindingPage, type Repository, type Scan } from "@/lib/api";
import { FindingTable } from "@/components/finding-table";
import { Panel } from "@/components/ui";
import { relativeTime, shortSha } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function RepositoryPage({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  const [repo, scans, findings] = await Promise.all([
    api<Repository>(`/api/v1/repositories/${id}`),
    api<Scan[]>(`/api/v1/repositories/${id}/scans`),
    api<FindingPage>(`/api/v1/orgs/${org}/findings?repository_id=${id}&limit=25`),
  ]);
  return (
    <div className="space-y-10">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">{repo.full_name}</h1>
        <p className="mt-1 text-muted">
          {repo.counts.total} open vulnerabilities, <span className="text-reach">{repo.counts.reachable} reachable</span>.
        </p>
        <p className="mt-3 flex flex-wrap gap-5 text-sm">
          <a className="underline underline-offset-4" href={`/api/v1/repositories/${id}/vex/preview?format=openvex`}>OpenVEX preview</a>
          {repo.latest_scan && <a className="underline underline-offset-4" href={`/api/v1/scans/${repo.latest_scan.id}/sbom`}>Download the SBOM</a>}
        </p>
      </header>
      <Panel title="Highest-risk findings">
        <FindingTable org={org} items={findings.items} />
      </Panel>
      <Panel title="Scans">
        <ul className="divide-y divide-line/60 text-sm">
          {scans.map((scan) => (
            <li key={scan.id} className="flex flex-wrap justify-between gap-4 py-2">
              <Link href={`/app/${org}/scans/${scan.id}`} className="hover:underline">
                <span className="font-mono">{shortSha(scan.commit_sha)}</span>, {scan.trigger.replace("_", " ")} scan, {scan.status}
              </Link>
              <span className="text-muted">{relativeTime(scan.created_at)}</span>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
