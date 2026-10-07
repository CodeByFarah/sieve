import Link from "next/link";
import { SieveField } from "@/components/sieve-field";
import { DemoRunButton } from "@/components/demo-run-button";
import { TraceGraph } from "@/components/trace-graph";
import { ScanTimeline } from "@/components/scan-timeline";
import { ThemeToggle } from "@/components/theme-toggle";
import { tryApi, type Demo, type FindingDetail, type Overview, type Scan, type ScanDetail } from "@/lib/api";

export const dynamic = "force-dynamic";

const RULES = [
  {
    verdict: "reachable",
    color: "text-reach",
    label: "Reachable",
    requires: "A chain of statically resolved calls from your code to a function the advisory concerns, verified to exist in the installed version.",
    never: "Never inferred from a name match, a reference, or a dynamic import.",
  },
  {
    verdict: "not_reached",
    color: "text-clear",
    label: "Not reached",
    requires: "A pinned version, at least one verified vulnerable function, a complete analysis, and no path of any kind to it, including uncertain ones.",
    never: "Never granted when anything on the way was too dynamic to follow.",
  },
  {
    verdict: "needs_review",
    color: "text-review",
    label: "Needs review",
    requires: "Everything else, with the rule that failed stated in words: no verified function, only dynamic paths, an unpinned version.",
    never: "Never rounded to an answer it cannot prove.",
  },
] as const;

export default async function Landing() {
  const [demo, overview] = await Promise.all([
    tryApi<Demo>("/api/v1/demo"),
    tryApi<Overview>("/api/v1/orgs/sieve-demo/overview"),
  ]);
  const totals = overview?.totals;
  const top = overview?.top_findings[0];
  const [detail, history] = await Promise.all([
    top ? tryApi<FindingDetail>(`/api/v1/findings/${top.id}`) : null,
    demo ? tryApi<Scan[]>(`/api/v1/repositories/${demo.repository_id}/scans`) : null,
  ]);
  // The newest scan may still be running; chart the newest one that finished.
  const finished = history?.find((s) => s.status === "succeeded");
  const scan = finished ? await tryApi<ScanDetail>(`/api/v1/scans/${finished.id}`) : null;
  const paths = detail?.analysis?.paths ?? [];
  const count = (verdict: string) =>
    totals ? (totals as unknown as Record<string, number>)[verdict] ?? 0 : null;

  return (
    <div className="mx-auto max-w-6xl px-6">
      <header className="flex items-center justify-between py-5">
        <span className="text-lg font-semibold tracking-tight">Sieve</span>
        <nav className="flex items-center gap-5 text-sm text-muted">
          <Link href="/app/sieve-demo" className="hover:text-text">Demo</Link>
          <ThemeToggle />
        </nav>
      </header>

      <main>
        <section className="grid items-center gap-12 py-16 md:grid-cols-[1.1fr_1fr] md:py-24">
          <div>
            <h1 className="max-w-xl text-4xl font-semibold leading-[1.1] tracking-tight md:text-[3.25rem]">
              {totals ? `Your scanner says ${totals.total} vulnerabilities.` : "Your scanner lists every vulnerable dependency."}{" "}
              Sieve shows the ones your code can actually reach.
            </h1>
            <p className="mt-6 max-w-lg text-lg text-muted">
              Evidence-backed vulnerability triage for Python repositories on GitHub: the call path behind each verdict,
              what an LLM contributed, and what was checked deterministically.
            </p>
            <div className="mt-8 flex flex-wrap items-start gap-4">
              <DemoRunButton />
              <Link href="/app/sieve-demo" className="rounded-md border border-line px-5 py-2.5 font-medium hover:border-muted">
                See the latest results
              </Link>
            </div>
            {demo && (
              <p className="mt-6 max-w-lg text-sm text-muted">
                Figures come from the most recent real scan of our deliberately vulnerable sample app, against advisory data
                recorded on {new Date(String(demo.snapshot.fetched_at)).toLocaleDateString("en-CA")}.
              </p>
            )}
          </div>
          {totals && totals.total > 0 ? (
            <SieveField counts={{ reachable: totals.reachable, needs_review: totals.needs_review, not_reached: totals.not_reached }} />
          ) : (
            <p className="text-muted">The demo has not been scanned on this deployment yet.</p>
          )}
        </section>

        {detail && paths.length > 0 && (
          <section className="border-t border-line py-16">
            <div className="grid gap-6 md:grid-cols-[1fr_1.6fr] md:items-end">
              <h2 className="text-2xl font-semibold tracking-tight">Every verdict comes with the path that proves it.</h2>
              <p className="text-muted">
                {detail.advisory.id} affects {detail.package} {detail.installed_version}. Sieve merged the {paths.length} strongest
                paths it found into one graph, from the entry points in the sample app to the vulnerable functions inside
                the package. Hover a function to isolate the paths through it.
              </p>
            </div>
            <div className="mt-10 rounded-lg border border-line bg-surface p-6">
              <TraceGraph paths={paths as never} verdict={detail.effective_verdict ?? null} />
            </div>
            <Link href={`/app/sieve-demo/findings/${detail.id}`} className="mt-5 inline-block text-sm underline underline-offset-4">
              Read the evidence line by line
            </Link>
          </section>
        )}

        <section className="border-t border-line py-16">
          <div className="grid gap-6 md:grid-cols-[1fr_1.6fr] md:items-end">
            <h2 className="text-2xl font-semibold tracking-tight">Three answers, and what each has to prove.</h2>
            <p className="text-muted">
              A wrong &ldquo;not affected&rdquo; can end up in a VEX statement sent to a customer, so the rules are deliberately
              lopsided. Dynamic code can push a finding towards &ldquo;needs review&rdquo;, never towards &ldquo;not reached&rdquo;.
            </p>
          </div>
          <div className="mt-10 overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead className="text-muted">
                <tr className="border-b border-line">
                  <th scope="col" className="w-40 pb-3 font-normal">Verdict</th>
                  <th scope="col" className="pb-3 font-normal">Requires</th>
                  <th scope="col" className="w-64 pb-3 font-normal">And</th>
                  <th scope="col" className="w-24 pb-3 text-right font-normal">In the demo</th>
                </tr>
              </thead>
              <tbody>
                {RULES.map((rule) => (
                  <tr key={rule.verdict} className="border-b border-line/60 align-top">
                    <th scope="row" className={`py-4 pr-6 text-base font-medium ${rule.color}`}>{rule.label}</th>
                    <td className="py-4 pr-6">{rule.requires}</td>
                    <td className="py-4 pr-6 text-muted">{rule.never}</td>
                    <td className={`py-4 text-right text-2xl font-semibold tabular-nums ${rule.color}`}>{count(rule.verdict) ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {scan?.started_at && scan.finished_at && (
          <section className="border-t border-line py-16">
            <div className="grid gap-6 md:grid-cols-[1fr_1.6fr] md:items-end">
              <h2 className="text-2xl font-semibold tracking-tight">One scan, stage by stage.</h2>
              <p className="text-muted">
                The pipeline persists every stage before starting the next, so progress you watch is real state and a crashed
                worker resumes where it stopped. These are the timings of the demo&apos;s most recent finished scan.
              </p>
            </div>
            <div className="mt-10">
              <ScanTimeline progress={scan.progress as never} startedAt={scan.started_at} finishedAt={scan.finished_at} />
            </div>
          </section>
        )}

        <section className="grid gap-12 border-t border-line py-16 md:grid-cols-2">
          <div>
            <h2 className="text-lg font-semibold">The model proposes; code decides.</h2>
            <p className="mt-2 text-muted">
              When an advisory doesn&apos;t name the vulnerable function, a model proposes candidates from the advisory and the
              upstream fix. Each must exist in the package&apos;s source and be touched by the fix, or it is discarded. On the
              golden dataset, no proposed function that does not exist has been accepted.
            </p>
          </div>
          <div>
            <h2 className="text-lg font-semibold">Your code is never run.</h2>
            <p className="mt-2 text-muted">
              Repositories and packages are parsed, never imported, installed or executed. Archives are extracted with path,
              link and size checks, and outbound requests go only to an allow-list of hosts.
            </p>
          </div>
        </section>

        <section className="border-t border-line py-16">
          <h2 className="text-2xl font-semibold tracking-tight">Find the vulnerabilities that actually matter.</h2>
          <div className="mt-6"><DemoRunButton /></div>
        </section>
      </main>
      <footer className="border-t border-line py-8 text-sm text-muted">
        Python and PyPI only for now. Static analysis has limits; they are documented, not hidden.
      </footer>
    </div>
  );
}
