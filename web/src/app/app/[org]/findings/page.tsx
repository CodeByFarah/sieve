import Link from "next/link";
import { api, type FindingPage } from "@/lib/api";
import { FindingTable } from "@/components/finding-table";
import { EmptyState } from "@/components/ui";

export const dynamic = "force-dynamic";

type Search = Record<string, string | string[] | undefined>;

const FILTERS = [
  ["All", {}],
  ["Reachable", { verdict: "reachable" }],
  ["Needs review", { verdict: "needs_review" }],
  ["Not reached", { verdict: "not_reached" }],
  ["Known exploited", { kev: "true" }],
  ["Critical and high", { severity: ["critical", "high"] }],
] as const;

function query(params: Record<string, string | readonly string[]>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    for (const v of Array.isArray(value) ? value : [value]) search.append(key, v as string);
  }
  return search.toString();
}

export default async function FindingsPage({ params, searchParams }: { params: Promise<{ org: string }>; searchParams: Promise<Search> }) {
  const { org } = await params;
  const raw = await searchParams;
  const current: Record<string, string | string[]> = {};
  for (const key of ["verdict", "severity", "kev", "package", "q", "sort", "cursor", "repository_id"]) {
    const value = raw[key];
    if (value) current[key] = value;
  }
  const page = await api<FindingPage>(`/api/v1/orgs/${org}/findings?${query(current)}`);
  const active = JSON.stringify({ ...current, cursor: undefined, sort: undefined, q: undefined });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
          <p className="mt-1 text-muted">{page.total} matching, highest risk first.</p>
        </div>
        <form className="flex gap-2" action={`/app/${org}/findings`}>
          {Object.entries(current).filter(([k]) => !["q", "cursor"].includes(k)).flatMap(([k, v]) =>
            (Array.isArray(v) ? v : [v]).map((value) => <input key={`${k}${value}`} type="hidden" name={k} value={value} />))}
          <label className="sr-only" htmlFor="q">Search findings</label>
          <input id="q" name="q" defaultValue={(current.q as string) ?? ""} placeholder="Advisory, package or text"
            className="w-64 rounded-md border border-line bg-surface px-3 py-1.5 text-sm" />
        </form>
      </div>
      <nav aria-label="Filters" className="flex flex-wrap gap-2">
        {FILTERS.map(([label, filter]) => {
          const selected = JSON.stringify({ ...filter, cursor: undefined, sort: undefined, q: undefined }) === active;
          return (
            <Link key={label} href={`/app/${org}/findings?${query(filter)}`} aria-current={selected ? "true" : undefined}
              className={`rounded-full border px-3 py-1 text-sm ${selected ? "border-text" : "border-line text-muted hover:text-text"}`}>
              {label}
            </Link>
          );
        })}
      </nav>
      {page.items.length === 0 ? (
        <EmptyState title="No findings match these filters." body="Try a different filter, or clear the search." />
      ) : (
        <FindingTable org={org} items={page.items} />
      )}
      {page.next_cursor && (
        <Link href={`/app/${org}/findings?${query({ ...current, cursor: page.next_cursor })}`} className="inline-block text-sm underline underline-offset-4">
          Show more
        </Link>
      )}
    </div>
  );
}
