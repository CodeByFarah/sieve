import Link from "next/link";
import { notFound } from "next/navigation";
import { api, ApiError, type FindingDetail } from "@/lib/api";
import { EvidencePath } from "@/components/evidence-path";
import { ReviewPanel } from "@/components/review-panel";
import { Kev, Panel, Severity, VerdictMark } from "@/components/ui";
import { ENTRYPOINT, REASONS, VERDICT_LABEL, percent, relativeTime, type Verdict } from "@/lib/format";

export const dynamic = "force-dynamic";

const ORIGIN: Record<string, string> = {
  advisory: "Named in the advisory",
  curated: "Curated by Sieve maintainers",
  ai: "Proposed by an LLM",
  reviewer: "Added by a reviewer",
};

function explanation(f: FindingDetail): string {
  const verdict = f.analysis?.verdict as Verdict | undefined;
  const path = f.analysis?.paths[0];
  const target = path?.steps.at(-1)?.symbol;
  if (verdict === "reachable" && path)
    return `Sieve found a static call path from ${ENTRYPOINT[path.entrypoint_kind]?.toLowerCase() ?? "application code"} ${path.steps[0].symbol} to ${target}, which this advisory concerns.`;
  const reason = f.analysis?.reasons[0];
  return String(reason?.message ?? "This finding has not been analysed yet.");
}

export default async function FindingPage({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  let f: FindingDetail;
  try {
    f = await api<FindingDetail>(`/api/v1/findings/${id}`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }
  const verdict = f.effective_verdict as Verdict | null;
  const analysis = f.analysis;
  const path = analysis?.paths[0];
  const statement = (f.vex_preview.statements as Record<string, string>[])[0];
  const risk = f.risk_breakdown as Record<string, Record<string, string | number | boolean | null>>;
  const reviewed = f.review_state === "accepted" || f.review_state === "overridden";

  return (
    <article className="space-y-10">
      <header>
        <Link href={`/app/${org}/findings`} className="text-sm text-muted hover:text-text">Findings</Link>
        <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-2">
          <span className="text-xl"><VerdictMark verdict={verdict} size="lg" /></span>
          {f.kev && <Kev />}
          {reviewed && <span className="text-sm text-muted">Reviewed{f.decided_verdict !== f.verdict ? " — analysis overridden" : ""}</span>}
          {f.review_state === "stale" && <span className="text-sm text-review">Review outdated by new analysis</span>}
        </div>
        <h1 className="mt-3 font-mono text-2xl">{f.advisory.id}</h1>
        <p className="mt-1 max-w-3xl text-lg">{f.advisory.summary}</p>
        <dl className="mt-4 flex flex-wrap gap-x-8 gap-y-2 text-sm">
          <div><dt className="text-muted">Package</dt><dd className="font-mono">{f.package} {f.installed_version ?? "(unpinned)"}</dd></div>
          <div><dt className="text-muted">Severity</dt><dd><Severity level={f.severity} />{f.advisory.cvss_score ? ` · CVSS ${f.advisory.cvss_score}` : ""}</dd></div>
          <div><dt className="text-muted">Confidence</dt><dd className="capitalize">{f.confidence ?? "—"}</dd></div>
          <div><dt className="text-muted">Risk</dt><dd className="tabular-nums">{f.risk_score == null ? "—" : Number(f.risk_score).toFixed(0)} / 100</dd></div>
          <div><dt className="text-muted">Repository</dt><dd>{f.repository_full_name}</dd></div>
          {f.advisory.aliases.length > 0 && <div><dt className="text-muted">Also known as</dt><dd className="font-mono">{f.advisory.aliases.join(", ")}</dd></div>}
        </dl>
      </header>

      <section>
        <h2 className="text-lg font-semibold">
          {verdict === "reachable" ? "Why Sieve thinks this is reachable" : verdict === "not_reached" ? "Why Sieve thinks this is not reached" : "Why this needs a person"}
        </h2>
        <p className="mt-2 max-w-3xl text-muted">{explanation(f)}</p>
        {analysis && (
          <ul className="mt-4 space-y-1 text-sm">
            {analysis.reasons.map((reason, i) => (
              <li key={i}>
                <span className="font-medium">{REASONS[String(reason.code)] ?? String(reason.code)}.</span>{" "}
                <span className="text-muted">{String(reason.message)}</span>
                {Array.isArray(reason.locations) && (
                  <ul className="ml-4 mt-1 font-mono text-xs text-muted">
                    {(reason.locations as { file: string; line: number; detail?: string }[]).map((loc, j) => (
                      <li key={j}>{loc.file}:{loc.line}{loc.detail ? ` (${loc.detail})` : ""}</li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="grid gap-10 lg:grid-cols-[1.5fr_1fr]">
        <div className="space-y-10">
          {path ? (
            <Panel title={verdict === "reachable" ? "Evidence: the call path" : "Closest path found"}>
              <EvidencePath steps={path.steps as never} entrypoint={path.entrypoint_kind} vulnerable={analysis?.verdict === "reachable"} />
              {analysis && analysis.paths.length > 1 && <p className="mt-4 text-sm text-muted">{analysis.paths.length - 1} more path{analysis.paths.length > 2 ? "s" : ""} reach other vulnerable symbols.</p>}
            </Panel>
          ) : (
            <Panel title="Evidence">
              <p className="text-muted">No path was found to show. The reasons above say what was checked.</p>
            </Panel>
          )}

          <Panel title="Vulnerable symbols and how they were verified">
            {f.symbols.length === 0 ? (
              <p className="text-muted">No vulnerable function is known for this advisory. Without one, Sieve cannot search for a path, so the finding stays in review.</p>
            ) : (
              <ul className="space-y-4">
                {f.symbols.map((symbol) => {
                  const checks = (symbol.verification_detail.checks ?? {}) as Record<string, { status: string; file?: string; line?: number }>;
                  return (
                    <li key={symbol.qualified_name}>
                      <p className="font-mono text-sm">{symbol.qualified_name}</p>
                      <p className="text-sm">
                        <span className={symbol.origin === "ai" ? "text-review" : "text-muted"}>{ORIGIN[symbol.origin]}</span>
                        {" · "}
                        <span className={symbol.verification === "verified" ? "text-clear" : symbol.verification === "rejected" ? "text-reach" : "text-muted"}>
                          {symbol.verification === "verified" ? "Verified in package source" : symbol.verification === "rejected" ? "Rejected by verification" : "Not yet verified"}
                        </span>
                      </p>
                      {Object.entries(checks).map(([version, check]) => (
                        <p key={version} className="font-mono text-xs text-muted">
                          {version}: {check.status === "found" ? `found at ${check.file}:${check.line}` : "not present in this version"}
                        </p>
                      ))}
                      {symbol.ai_extraction && (
                        <p className="mt-1 text-xs text-muted">
                          AI-generated by {symbol.ai_extraction.model} ({symbol.ai_extraction.prompt_version}), {relativeTime(symbol.ai_extraction.created_at)}.
                        </p>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
            <p className="mt-4 text-xs text-muted">{f.symbol_provenance}</p>
          </Panel>
        </div>

        <aside className="space-y-10">
          <Panel title="Risk score">
            <p className="text-sm text-muted">{String(risk.formula ?? "")}</p>
            <dl className="mt-3 space-y-1 text-sm">
              <div className="flex justify-between"><dt>Severity ({String(risk.severity?.level)})</dt><dd className="tabular-nums">{String(risk.severity?.points)} pts</dd></div>
              <div className="flex justify-between"><dt>Exploitation ({String(risk.exploitation?.basis)})</dt><dd className="tabular-nums">{String(risk.exploitation?.points)} pts</dd></div>
              <div className="flex justify-between"><dt>Reachability ({String(risk.reachability?.verdict).replace("_", " ")})</dt><dd className="tabular-nums">× {String(risk.reachability?.factor)}</dd></div>
              <div className="flex justify-between border-t border-line pt-1 font-medium"><dt>Score</dt><dd className="tabular-nums">{String(risk.score)}</dd></div>
            </dl>
            {f.exploitation.epss && <p className="mt-2 text-xs text-muted">EPSS {percent(String(f.exploitation.epss.score))} probability, {percent(String(f.exploitation.epss.percentile))} percentile ({String(f.exploitation.epss.date)})</p>}
          </Panel>

          <Panel title="Recommended action">
            <p className="text-sm">
              {verdict === "reachable"
                ? `Upgrade ${f.package} to a fixed version. Until then, avoid passing untrusted input to the code on the path above.`
                : verdict === "needs_review"
                  ? "Read the reasons and the advisory, then record a decision below."
                  : `No action needed beyond routine upgrades. Consider removing ${f.package} if nothing uses it.`}
            </p>
          </Panel>

          <Panel title="VEX statement">
            <p className="flex items-center gap-2 text-sm">
              <span aria-hidden className={`h-2 w-2 rounded-full ${statement.status === "not_affected" ? "bg-clear" : statement.status === "affected" ? "bg-reach" : "bg-review"}`} />
              {statement.status.replace("_", " ")}{statement.justification ? ` — ${statement.justification.replaceAll("_", " ")}` : ""}
            </p>
            <p className="mt-1 text-sm text-muted">{statement.impact_statement ?? statement.action_statement ?? statement.status_notes}</p>
            <details className="mt-3 text-sm">
              <summary className="cursor-pointer text-muted">OpenVEX JSON</summary>
              <pre className="mt-2 max-h-72 overflow-auto rounded border border-line bg-surface p-3 font-mono text-xs">{JSON.stringify(f.vex_preview, null, 2)}</pre>
            </details>
          </Panel>

          <Panel title="Review">
            {f.reviews.length > 0 && (
              <ul className="mb-4 space-y-3 text-sm">
                {f.reviews.map((review) => (
                  <li key={review.id}>
                    <p><span className="font-medium">{review.reviewer_login}</span> decided <span className="font-medium">{VERDICT_LABEL[review.decided_verdict as Verdict]}</span>, VEX {review.vex_status.replace("_", " ")}</p>
                    {review.comment && <p className="text-muted">{review.comment}</p>}
                    <p className="text-xs text-muted">{relativeTime(review.created_at)}</p>
                  </li>
                ))}
              </ul>
            )}
            {f.can_review && analysis ? (
              <ReviewPanel findingId={f.id} version={f.version} analysedVerdict={analysis.verdict as Verdict} />
            ) : (
              <p className="text-sm text-muted">{org === "sieve-demo" ? "The demo is read-only. Install Sieve on your own repositories to review findings." : "You can view this finding but not review it."}</p>
            )}
          </Panel>
        </aside>
      </div>

      <Panel title="History">
        <ol className="space-y-2 text-sm">
          {f.timeline.map((event) => (
            <li key={event.seq} className="grid grid-cols-[9rem_1fr] gap-4">
              <time className="text-muted" dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString("en-CA")}</time>
              <details>
                <summary className="cursor-pointer">{event.action.replace(".", " ").replace("_", " ")}{event.actor_login ? ` by ${event.actor_login}` : ""}</summary>
                <pre className="mt-1 overflow-x-auto font-mono text-xs text-muted">{JSON.stringify(event.data, null, 2)}</pre>
              </details>
            </li>
          ))}
        </ol>
      </Panel>
    </article>
  );
}
