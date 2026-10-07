"use client";

import { useMemo, useState } from "react";
import { VERDICT_LABEL, type Verdict } from "@/lib/format";

export type MapItem = {
  id: string;
  advisory_id: string;
  package: string;
  installed_version: string;
  severity: string;
  cvss_score: string | number | null;
  epss_percentile: string | number | null;
  effective_verdict: Verdict | null;
  kev: boolean;
};

const W = 1040;
const H = 430;
const M = { top: 30, right: 18, bottom: 44, left: 96 };
const STRIP = 34; // column for findings with no EPSS score, left of the axis
const PLOT_L = M.left + STRIP + 14;
const PLOT_W = W - PLOT_L - M.right;
const PLOT_H = H - M.top - M.bottom;
const ZONE_EPSS = 0.9;
const ZONE_CVSS = 7;

// When a record has no CVSS vector, the advisory's severity band stands in, drawn hollow.
const BAND: Record<string, number> = { critical: 9.5, high: 8, medium: 5.5, low: 2.5 };
const COLOR: Record<Verdict, string> = { reachable: "var(--reach)", needs_review: "var(--review)", not_reached: "var(--clear)" };
const ORDER: Verdict[] = ["not_reached", "needs_review", "reachable"];

/** Deterministic jitter in [-1, 1] so overlapping findings separate the same way on every render. */
function jitter(id: string, salt: number): number {
  let h = 2166136261 ^ salt;
  for (let i = 0; i < id.length; i++) h = Math.imul(h ^ id.charCodeAt(i), 16777619);
  return ((h >>> 0) % 2000) / 1000 - 1;
}

const xOf = (p: number) => PLOT_L + p * PLOT_W;
const yOf = (cvss: number) => M.top + (1 - cvss / 10) * PLOT_H;

/**
 * Every open finding placed by how likely its vulnerability is to be exploited (EPSS percentile)
 * and how bad it would be (CVSS), coloured by reachability. The corner that is both severe and
 * likely to be exploited is shaded: reachable findings there are the work for this week.
 */
export function ExposureMap({ items, org }: { items: MapItem[]; org: string }) {
  const [hidden, setHidden] = useState<Set<Verdict>>(new Set());
  const [hover, setHover] = useState<string | null>(null);

  const points = useMemo(
    () =>
      items
        .filter((f) => f.effective_verdict)
        .map((f) => {
          const epss = f.epss_percentile === null ? null : Number(f.epss_percentile);
          const measured = f.cvss_score !== null;
          const cvss = measured ? Number(f.cvss_score) : BAND[f.severity] ?? 0;
          const x = epss === null ? M.left + STRIP / 2 + jitter(f.id, 1) * 9 : xOf(epss) + jitter(f.id, 1) * 5;
          const y = Math.min(Math.max(yOf(cvss) + jitter(f.id, 2) * 6, M.top + 5), H - M.bottom - 5);
          const zone = epss !== null && epss >= ZONE_EPSS && cvss >= ZONE_CVSS;
          return { ...f, verdict: f.effective_verdict as Verdict, epss, cvss, measured, x, y, zone };
        })
        .sort((a, b) => ORDER.indexOf(a.verdict) - ORDER.indexOf(b.verdict)),
    [items],
  );

  const counts = Object.fromEntries(ORDER.map((v) => [v, points.filter((p) => p.verdict === v).length])) as Record<Verdict, number>;
  const urgent = points.filter((p) => p.zone && p.verdict === "reachable").length;
  const inZone = points.filter((p) => p.zone).length;
  const current = points.find((p) => p.id === hover);
  const toggle = (v: Verdict) =>
    setHidden((h) => {
      const next = new Set(h);
      if (next.has(v)) next.delete(v);
      else next.add(v);
      return next;
    });

  return (
    <figure>
      <p className="max-w-2xl text-sm text-muted">
        {inZone === 0
          ? "No finding is both high severity and in the top tenth of exploitation likelihood."
          : `${inZone} finding${inZone === 1 ? " is" : "s are"} high severity and in the top tenth of exploitation likelihood; `}
        {inZone > 0 && (
          <strong className={urgent ? "font-medium text-reach" : "font-medium text-text"}>
            {urgent} of them {urgent === 1 ? "is" : "are"} reachable from your code.
          </strong>
        )}
      </p>

      <div className="relative mt-4 overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full min-w-[640px]" role="img"
          aria-label={`Exposure map of ${points.length} findings by exploitation likelihood and severity`}>
          {/* the corner that matters */}
          <rect x={xOf(ZONE_EPSS)} y={yOf(10)} width={xOf(1) - xOf(ZONE_EPSS)} height={yOf(ZONE_CVSS) - yOf(10)}
            fill="var(--reach)" fillOpacity={0.07} stroke="var(--reach)" strokeOpacity={0.35} strokeDasharray="3 3" />
          <text x={xOf(1)} y={M.top - 10} fontSize={11} textAnchor="end" fill="var(--reach)">fix first: high severity, top tenth by EPSS</text>

          {/* severity bands on the y axis, at the CVSS v3 boundaries */}
          {[
            [9, "critical"],
            [7, "high"],
            [4, "medium"],
            [0.1, "low"],
          ].map(([v, label]) => (
            <g key={label as string}>
              <line x1={M.left} x2={W - M.right} y1={yOf(v as number)} y2={yOf(v as number)} stroke="var(--line)" strokeOpacity={0.7} />
              <text x={M.left - 10} y={yOf(v as number) + 4} fontSize={11} textAnchor="end" fill="var(--muted)">{label}</text>
            </g>
          ))}
          <text x={14} y={M.top + PLOT_H / 2} fontSize={11} fill="var(--muted)" transform={`rotate(-90 14 ${M.top + PLOT_H / 2})`} textAnchor="middle">
            severity (CVSS)
          </text>

          {/* x axis: EPSS percentile */}
          {[0, 0.5, 0.9, 1].map((p) => (
            <g key={p}>
              <line x1={xOf(p)} x2={xOf(p)} y1={M.top} y2={H - M.bottom} stroke="var(--line)" strokeOpacity={p === 0 ? 1 : 0.45} />
              <text x={xOf(p)} y={H - M.bottom + 16} fontSize={11} textAnchor="middle" fill="var(--muted)">{Math.round(p * 100)}</text>
            </g>
          ))}
          <text x={PLOT_L + PLOT_W / 2} y={H - 6} fontSize={11} textAnchor="middle" fill="var(--muted)">
            exploitation likelihood (EPSS percentile)
          </text>
          <rect x={M.left} y={M.top} width={STRIP} height={PLOT_H} fill="var(--raised)" opacity={0.6} />
          <text x={M.left + STRIP / 2} y={H - M.bottom + 16} fontSize={10} textAnchor="middle" fill="var(--muted)">no score</text>

          {points.map((p) => {
            if (hidden.has(p.verdict)) return null;
            const dim = hover !== null && hover !== p.id;
            return (
              <a key={p.id} href={`/app/${org}/findings/${p.id}`}
                aria-label={`${p.advisory_id} in ${p.package}, ${VERDICT_LABEL[p.verdict]}`}
                onMouseEnter={() => setHover(p.id)} onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(p.id)} onBlur={() => setHover(null)}
                className="outline-none [&:focus-visible>circle:first-child]:stroke-[var(--focus)]">
                {p.kev && <circle cx={p.x} cy={p.y} r={8.5} fill="none" stroke="var(--text)" strokeWidth={1.25} opacity={dim ? 0.3 : 1} />}
                <circle cx={p.x} cy={p.y} r={hover === p.id ? 6.5 : 4.5}
                  fill={p.measured ? COLOR[p.verdict] : "var(--bg)"} stroke={COLOR[p.verdict]} strokeWidth={p.measured ? 0 : 1.5}
                  opacity={dim ? 0.25 : p.verdict === "not_reached" ? 0.75 : 1} className="transition-[r,opacity] duration-150" />
              </a>
            );
          })}
        </svg>

        {current && (
          <div role="status" className="pointer-events-none absolute z-10 w-64 rounded-md border border-line bg-surface px-3 py-2 text-xs shadow-lg"
            style={{ left: `min(calc(${(current.x / W) * 100}% + 12px), calc(100% - 16.5rem))`, top: `calc(${(current.y / H) * 100}% + 14px)` }}>
            <p className="font-mono text-sm">{current.advisory_id}</p>
            <p className="text-muted">{current.package} {current.installed_version}</p>
            <p className="mt-1">
              <span style={{ color: COLOR[current.verdict] }}>{VERDICT_LABEL[current.verdict]}</span>
              {current.kev && <span>, known exploited</span>}
            </p>
            <p className="mt-1 text-muted">
              {current.measured ? `CVSS ${current.cvss.toFixed(1)}` : `${current.severity} (no CVSS vector)`}, EPSS{" "}
              {current.epss === null ? "not scored" : `${Math.round(current.epss * 100)}th percentile`}
            </p>
          </div>
        )}
      </div>

      <figcaption className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted">
        {ORDER.slice().reverse().map((v) => (
          <button key={v} type="button" onClick={() => toggle(v)} aria-pressed={!hidden.has(v)}
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 transition-colors ${hidden.has(v) ? "border-line opacity-50" : "border-muted/40 text-text"}`}>
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: COLOR[v] }} />
            {VERDICT_LABEL[v]} <span className="tabular-nums text-muted">{counts[v]}</span>
          </button>
        ))}
        <span className="ml-2 inline-flex items-center gap-2">
          <svg width="18" height="18" aria-hidden><circle cx="9" cy="9" r="7" fill="none" stroke="var(--text)" strokeWidth="1.25" /><circle cx="9" cy="9" r="3.5" fill="var(--muted)" /></svg>
          known exploited (CISA KEV)
        </span>
        <span className="inline-flex items-center gap-2">
          <svg width="12" height="12" aria-hidden><circle cx="6" cy="6" r="4.5" fill="none" stroke="var(--muted)" strokeWidth="1.5" /></svg>
          severity band only, no CVSS vector
        </span>
      </figcaption>
    </figure>
  );
}
