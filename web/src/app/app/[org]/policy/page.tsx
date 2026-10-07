import { api, type Policy } from "@/lib/api";
import { Panel } from "@/components/ui";

export const dynamic = "force-dynamic";

type Rule = { action: "block" | "warn"; when: Record<string, unknown>; description?: string };

function describe(when: Record<string, unknown>): string {
  const parts: string[] = [];
  if (when.kev === true) parts.push("it is known to be exploited");
  if (Array.isArray(when.verdict)) parts.push(`reachability is ${(when.verdict as string[]).map((v) => v.replace("_", " ")).join(" or ")}`);
  if (when.severity_at_least) parts.push(`severity is ${String(when.severity_at_least)} or higher`);
  if (when.epss_percentile_at_least) parts.push(`EPSS percentile is at least ${String(when.epss_percentile_at_least)}`);
  return parts.length ? parts.join(", and ") : "always";
}

export default async function PolicyPage({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const policy = await api<Policy>(`/api/v1/orgs/${org}/policy`);
  const rules = (policy.rules.rules ?? []) as Rule[];
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Pull request policy</h1>
        <p className="mt-1 max-w-2xl text-muted">
          Applied only to vulnerabilities a pull request introduces or makes reachable. The first matching rule decides; a check
          lists every finding with the rule that matched it. Version {policy.version}.
        </p>
      </div>
      <Panel title="Rules">
        <ol className="space-y-3">
          {rules.map((rule, index) => (
            <li key={index} className="grid grid-cols-[4rem_1fr] gap-4">
              <span className={rule.action === "block" ? "font-medium text-reach" : "font-medium text-review"}>{rule.action === "block" ? "Block" : "Warn"}</span>
              <span>when {describe(rule.when)}{rule.description ? <span className="block text-sm text-muted">{rule.description}</span> : null}</span>
            </li>
          ))}
        </ol>
      </Panel>
      <Panel title="Version history">
        <ul className="text-sm text-muted">
          {policy.history.map((h) => <li key={String(h.version)}>Version {String(h.version)}, {new Date(String(h.created_at)).toLocaleString("en-CA")}</li>)}
        </ul>
        {!policy.can_edit && <p className="mt-3 text-sm text-muted">Only organization admins can change the policy.</p>}
      </Panel>
    </div>
  );
}
