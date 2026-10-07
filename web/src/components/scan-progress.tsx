"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { STAGE_LABEL } from "@/lib/format";

type Stage = { status: string; duration_seconds?: number; counts?: Record<string, unknown> };
type ScanState = {
  id: string;
  status: string;
  stage: string | null;
  stages: string[];
  progress: Record<string, Stage>;
  commit_sha: string;
  repository_full_name: string;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
  correlation_id?: string | null;
};

function summary(name: string, counts: Record<string, unknown> | undefined): string | null {
  if (!counts) return null;
  if (name === "inventory") return `${counts.dependencies} dependencies, ${counts.pinned} pinned`;
  if (name === "match") return `${counts.findings} vulnerabilities matched`;
  if (name === "symbols") return `${counts.with_symbols} with known vulnerable functions`;
  if (name === "callgraph") return `${counts.app_modules} app modules, ${counts.dependency_modules} dependency modules, ${counts.edges} call edges`;
  if (name === "reachability") return `${counts.reachable ?? 0} reachable, ${counts.needs_review ?? 0} need review, ${counts.not_reached ?? 0} not reached`;
  return null;
}

/** Live view of a scan. Every update is the scan's own persisted record, streamed over SSE. */
export function ScanProgress({ initial }: { initial: ScanState }) {
  const [scan, setScan] = useState(initial);
  const [now, setNow] = useState(() => Date.now());
  const router = useRouter();
  const finished = ["succeeded", "failed", "cancelled"].includes(scan.status);

  useEffect(() => {
    if (finished) return;
    const source = new EventSource(`/api/v1/scans/${initial.id}/events`);
    source.addEventListener("scan", (event) => setScan(JSON.parse((event as MessageEvent).data)));
    source.addEventListener("done", () => { source.close(); router.refresh(); });
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => { source.close(); clearInterval(tick); };
  }, [initial.id, finished, router]);

  const end = scan.finished_at ? new Date(scan.finished_at).getTime() : now;
  const elapsed = scan.started_at ? Math.max(0, Math.round((end - new Date(scan.started_at).getTime()) / 1000)) : 0;

  return (
    <div>
      <p className="text-sm text-muted" aria-live="polite">
        {scan.repository_full_name} at <span className="font-mono">{scan.commit_sha.slice(0, 7)}</span> ·{" "}
        {scan.status === "queued" ? "waiting for a worker" : scan.status === "running" ? `running for ${elapsed}s` : `${scan.status} in ${elapsed}s`}
      </p>
      <ol className="mt-5 space-y-3">
        {scan.stages.map((name) => {
          const stage = scan.progress[name];
          const state = stage?.status ?? "waiting";
          const detail = summary(name, stage?.counts);
          return (
            <li key={name} className="grid grid-cols-[1.25rem_1fr_auto] items-baseline gap-3">
              <span aria-hidden className="text-center">
                {state === "done" ? "✓" : state === "running" ? <span className="animate-pulse-dot inline-block h-2 w-2 rounded-full bg-text" /> : state === "failed" ? "✕" : <span className="inline-block h-2 w-2 rounded-full border border-muted" />}
              </span>
              <span className={state === "waiting" ? "text-muted" : ""}>
                {STAGE_LABEL[name] ?? name}
                {detail && <span className="block text-sm text-muted">{detail}</span>}
              </span>
              <span className="font-mono text-xs text-muted">{stage?.duration_seconds !== undefined ? `${stage.duration_seconds.toFixed(1)}s` : ""}</span>
            </li>
          );
        })}
      </ol>
      {scan.status === "failed" && (
        <p role="alert" className="mt-5 text-reach">
          {scan.error_message ?? "The scan failed."} Your repository was not modified.
        </p>
      )}
    </div>
  );
}
