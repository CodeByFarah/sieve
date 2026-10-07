import Link from "next/link";
import { VERDICT_BG, VERDICT_LABEL, VERDICT_TEXT, type Verdict } from "@/lib/format";

export function VerdictMark({ verdict, size = "md" }: { verdict: Verdict | null | undefined; size?: "md" | "lg" }) {
  if (!verdict) return <span className="text-muted">Pending</span>;
  const dot = size === "lg" ? "h-3 w-3" : "h-2 w-2";
  return (
    <span className={`inline-flex items-center gap-2 font-medium ${VERDICT_TEXT[verdict]}`}>
      <span aria-hidden className={`${dot} rounded-full ${VERDICT_BG[verdict]}`} />
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"] as const;

export function Severity({ level }: { level: string }) {
  const filled = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }[level] ?? 0;
  return (
    <span className="inline-flex items-center gap-2 capitalize" title={`Severity: ${level}`}>
      <span aria-hidden className="flex gap-0.5">
        {[0, 1, 2, 3].map((i) => (
          <span key={i} className={`h-2.5 w-1 rounded-sm ${i < filled ? "bg-text" : "bg-line"}`} />
        ))}
      </span>
      {level}
    </span>
  );
}
Severity.order = SEVERITY_ORDER;

export function Kev() {
  return (
    <span
      className="rounded border border-reach/60 px-1.5 py-0.5 text-xs text-reach"
      title="Listed in CISA's Known Exploited Vulnerabilities catalog"
    >
      Known exploited
    </span>
  );
}

export function Panel({ title, children, aside }: { title?: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <section className="border-t border-line pt-5">
      {title && (
        <div className="mb-4 flex items-baseline justify-between gap-4">
          <h2 className="text-base font-semibold">{title}</h2>
          {aside}
        </div>
      )}
      {children}
    </section>
  );
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-line px-6 py-10">
      <p className="font-medium">{title}</p>
      <p className="mt-1 max-w-prose text-muted">{body}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ title, body, correlationId }: { title: string; body: string; correlationId?: string | null }) {
  return (
    <div role="alert" className="rounded-lg border border-reach/40 px-6 py-8">
      <p className="font-medium">{title}</p>
      <p className="mt-1 max-w-prose text-muted">{body}</p>
      {correlationId && <p className="mt-3 font-mono text-xs text-muted">Error ID: {correlationId}</p>}
    </div>
  );
}

export function ButtonLink({ href, children, quiet }: { href: string; children: React.ReactNode; quiet?: boolean }) {
  const style = quiet
    ? "border border-line hover:border-muted"
    : "bg-text text-bg hover:opacity-90";
  return (
    <Link href={href} className={`inline-flex items-center rounded-md px-4 py-2 text-sm font-medium transition ${style}`}>
      {children}
    </Link>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded bg-raised ${className}`} />;
}
