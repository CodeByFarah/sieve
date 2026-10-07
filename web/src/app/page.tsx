import Link from "next/link";
import { SieveField } from "@/components/sieve-field";
import { DemoRunButton } from "@/components/demo-run-button";
import { EvidencePath } from "@/components/evidence-path";
import { ThemeToggle } from "@/components/theme-toggle";
import { tryApi, type Demo, type FindingDetail, type Overview } from "@/lib/api";

export const dynamic = "force-dynamic";

const STEPS = [
  ["Inventory", "Reads lockfiles and produces a CycloneDX SBOM. Nothing is installed or executed."],
  ["Intelligence", "Matches pinned versions against OSV advisories, with CISA KEV and EPSS for urgency."],
  ["Vulnerable functions", "Finds which functions each advisory concerns and checks them against the package's real source."],
  ["Reachability", "Builds a call graph over your code and its dependencies and searches for a path."],
  ["Decision", "A person reviews the evidence; the decision becomes an OpenVEX or CycloneDX statement."],
];

export default async function Landing() {
  const [demo, overview] = await Promise.all([
    tryApi<Demo>("/api/v1/demo"),
    tryApi<Overview>("/api/v1/orgs/sieve-demo/overview"),
  ]);
  const totals = overview?.totals;
  const top = overview?.top_findings[0];
  const detail = top ? await tryApi<FindingDetail>(`/api/v1/findings/${top.id}`) : null;
  const path = detail?.analysis?.paths[0];

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

      {path && detail && (
        <section className="grid gap-10 border-t border-line py-16 md:grid-cols-[1fr_1.4fr]">
          <div>
            <h2 className="text-2xl font-semibold tracking-tight">Every verdict comes with its evidence.</h2>
            <p className="mt-4 text-muted">
              {detail.advisory.id} affects {detail.package} {detail.installed_version}. Sieve traced a path from an HTTP route
              in the sample app to the vulnerable function and shows the exact lines.
            </p>
            <Link href={`/app/sieve-demo/findings/${detail.id}`} className="mt-6 inline-block underline underline-offset-4">
              Open this finding
            </Link>
          </div>
          <EvidencePath steps={path.steps as never} entrypoint={path.entrypoint_kind} vulnerable />
        </section>
      )}

      <section className="border-t border-line py-16">
        <h2 className="text-2xl font-semibold tracking-tight">How a scan works</h2>
        <ol className="mt-8 grid gap-8 md:grid-cols-5">
          {STEPS.map(([title, body], index) => (
            <li key={title}>
              <p className="font-mono text-sm text-muted">{index + 1}</p>
              <p className="mt-1 font-medium">{title}</p>
              <p className="mt-2 text-sm text-muted">{body}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="grid gap-12 border-t border-line py-16 md:grid-cols-3">
        <div>
          <h3 className="font-semibold">AI proposes, code decides</h3>
          <p className="mt-2 text-muted">
            When an advisory doesn&apos;t name the vulnerable function, a model proposes candidates from the advisory and the
            upstream fix. Each must exist in the package&apos;s source and relate to the fix, or it is discarded. The model
            never decides reachability.
          </p>
        </div>
        <div>
          <h3 className="font-semibold">Your code is never run</h3>
          <p className="mt-2 text-muted">
            Repositories and packages are parsed, never imported, installed or executed. Archives are extracted with path,
            link and size checks; outbound requests go only to an allow-list of hosts.
          </p>
        </div>
        <div>
          <h3 className="font-semibold">Unknown stays unknown</h3>
          <p className="mt-2 text-muted">
            When analysis can&apos;t establish a path or rule one out, the finding says “needs review” and explains why. A wrong
            “not affected” is worse than an honest “we couldn&apos;t tell”.
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
