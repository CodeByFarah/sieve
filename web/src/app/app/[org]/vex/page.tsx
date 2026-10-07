import { api, type Repository, type VexDocument } from "@/lib/api";
import { EmptyState, Panel } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function VexPage({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const [documents, repos] = await Promise.all([
    api<VexDocument[]>(`/api/v1/orgs/${org}/vex`),
    api<Repository[]>(`/api/v1/orgs/${org}/repositories`),
  ]);
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">VEX</h1>
        <p className="mt-1 max-w-2xl text-muted">
          Statements come from reviewed findings only. Anything not yet reviewed is published as “under investigation”, never as
          a definitive status. Every document is validated against the official OpenVEX or CycloneDX schema.
        </p>
      </div>
      <Panel title="Current statements">
        <ul className="space-y-2 text-sm">
          {repos.map((repo) => (
            <li key={repo.id} className="flex flex-wrap justify-between gap-4">
              <span>{repo.full_name}</span>
              <span className="space-x-4">
                <a className="underline underline-offset-4" href={`/api/v1/repositories/${repo.id}/vex/preview?format=openvex`}>OpenVEX</a>
                <a className="underline underline-offset-4" href={`/api/v1/repositories/${repo.id}/vex/preview?format=cyclonedx`}>CycloneDX VEX</a>
              </span>
            </li>
          ))}
        </ul>
      </Panel>
      <Panel title="Generated documents">
        {documents.length === 0 ? (
          <EmptyState title="No VEX documents generated yet." body="Members can generate a signed-off document for a repository; it is stored with its SHA-256 for later verification." />
        ) : (
          <ul className="divide-y divide-line/60 text-sm">
            {documents.map((doc) => (
              <li key={doc.id} className="flex flex-wrap justify-between gap-4 py-2">
                <span>{doc.repository_full_name} · {doc.format} · {doc.statement_count} statements</span>
                <a className="underline underline-offset-4" href={`/api/v1/vex/${doc.id}/download`}>Download</a>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
