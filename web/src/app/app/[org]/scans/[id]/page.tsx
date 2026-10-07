import Link from "next/link";
import { api, type ScanDetail } from "@/lib/api";
import { ScanProgress } from "@/components/scan-progress";
import { Panel } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function ScanPage({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  const scan = await api<ScanDetail>(`/api/v1/scans/${id}`);
  const done = scan.status === "succeeded";
  return (
    <div className="space-y-10">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Scan of {scan.repository_full_name}</h1>
      </header>
      <ScanProgress initial={scan as never} />
      {done && (
        <p>
          <Link href={`/app/${org}/findings`} className="rounded-md bg-text px-4 py-2 text-sm font-medium text-bg">See the findings</Link>
        </p>
      )}
      {scan.manifests.length > 0 && (
        <Panel title="Manifests read">
          <ul className="space-y-1 text-sm">
            {scan.manifests.map((m) => (
              <li key={m.path}>
                <span className="font-mono">{m.path}</span> <span className="text-muted">{m.format} · {m.status}</span>
                {m.detail && <span className="block text-xs text-muted">{m.detail}</span>}
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}
