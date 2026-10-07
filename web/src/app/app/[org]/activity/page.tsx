import { api, type AuditEvent } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function ActivityPage({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const data = await api<{ events: AuditEvent[]; chain: { valid: boolean; events_checked: number } }>(`/api/v1/orgs/${org}/activity`);
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Activity</h1>
        <p className={`mt-1 text-sm ${data.chain.valid ? "text-muted" : "text-reach"}`}>
          {data.chain.valid
            ? `Audit log intact: all ${data.chain.events_checked} events verify against their hash chain.`
            : "The audit log's hash chain does not verify. An event was altered outside the application."}
        </p>
      </div>
      <ol className="divide-y divide-line/60">
        {data.events.map((event) => (
          <li key={event.seq} className="grid gap-1 py-3 sm:grid-cols-[11rem_1fr]">
            <time className="text-sm text-muted" dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString("en-CA")}</time>
            <details>
              <summary className="cursor-pointer">
                {event.action}
                {event.actor_login ? ` by ${event.actor_login}` : ` by ${event.actor_type}`}
              </summary>
              <pre className="mt-2 overflow-x-auto font-mono text-xs text-muted">{JSON.stringify({ target: `${event.target_type}/${event.target_id}`, ...event.data, correlation_id: event.correlation_id }, null, 2)}</pre>
            </details>
          </li>
        ))}
      </ol>
    </div>
  );
}
