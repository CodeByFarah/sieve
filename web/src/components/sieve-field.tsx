"use client";

import { useEffect, useMemo, useState } from "react";

type Counts = { reachable: number; needs_review: number; not_reached: number };

const BINS = [
  { key: "reachable", label: "reachable", color: "var(--reach)" },
  { key: "needs_review", label: "need review", color: "var(--review)" },
  { key: "not_reached", label: "not reached", color: "var(--clear)" },
] as const;

/** One dot per real finding from the latest demo scan. They start as an undifferentiated cloud
 * above the mesh and fall through it into three bins. Plays once; skipped for reduced motion. */
export function SieveField({ counts }: { counts: Counts }) {
  const [settled, setSettled] = useState(false);
  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const timer = setTimeout(() => setSettled(true), reduce ? 0 : 600);
    return () => clearTimeout(timer);
  }, []);

  const dots = useMemo(() => {
    const items: { bin: number; cloudX: number; cloudY: number; binX: number; binY: number; delay: number }[] = [];
    let seed = 7;
    const random = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    BINS.forEach((bin, b) => {
      const n = counts[bin.key];
      for (let i = 0; i < n; i++) {
        const column = i % 8;
        const row = Math.floor(i / 8);
        items.push({
          bin: b,
          cloudX: 20 + random() * 360,
          cloudY: 14 + random() * 70,
          binX: 28 + b * 132 + column * 11,
          binY: 236 - row * 11,
          delay: random() * 900,
        });
      }
    });
    return items;
  }, [counts]);

  const total = counts.reachable + counts.needs_review + counts.not_reached;
  return (
    <figure className="w-full max-w-[420px]">
      <svg viewBox="0 0 400 290" className="w-full" role="img"
        aria-label={`${total} findings: ${counts.reachable} reachable, ${counts.needs_review} need review, ${counts.not_reached} not reached`}>
        {/* the mesh */}
        <g stroke="var(--line)" strokeWidth="1">
          {Array.from({ length: 21 }, (_, i) => (
            <line key={`v${i}`} x1={20 + i * 18} x2={20 + i * 18} y1={104} y2={118} />
          ))}
          <line x1={20} x2={380} y1={104} y2={104} />
          <line x1={20} x2={380} y1={118} y2={118} />
        </g>
        {BINS.map((bin, b) => (
          <line key={bin.key} x1={20 + b * 132} x2={116 + b * 132} y1={246} y2={246} stroke="var(--line)" />
        ))}
        {dots.map((dot, i) => (
          <circle
            key={i}
            r={3.6}
            fill={settled ? BINS[dot.bin].color : "var(--muted)"}
            style={{
              transform: `translate(${settled ? dot.binX : dot.cloudX}px, ${settled ? dot.binY : dot.cloudY}px)`,
              transition: `transform 1.1s cubic-bezier(.5,0,.2,1) ${dot.delay}ms, fill .4s ease ${dot.delay + 500}ms`,
            }}
          />
        ))}
        {BINS.map((bin, b) => (
          <text key={bin.key} x={20 + b * 132} y={272} fill="var(--text)" fontSize="13">
            <tspan fontWeight={600} fill={bin.color}>{counts[bin.key]}</tspan> {bin.label}
          </text>
        ))}
      </svg>
    </figure>
  );
}
