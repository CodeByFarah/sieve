"use client";

import { useMemo, useState } from "react";
import { ENTRYPOINT } from "@/lib/format";

type Step = {
  symbol: string;
  kind: string;
  package: string | null;
  file: string;
  line: number;
  call: { edge: string } | null;
};
type TracePath = { rank: number; entrypoint_kind: string; steps: Step[] };

type Node = {
  id: string;
  pkg: string | null;
  file: string;
  line: number;
  depth: number;
  row: number;
  terminal: boolean;
  entry: string | null;
  paths: Set<number>;
};
type Edge = { from: string; to: string; kind: string; paths: Set<number> };

const STRONG = new Set(["call", "method", "import"]);
const EDGE_WORD: Record<string, string> = {
  call: "calls",
  method: "calls (receiver inferred)",
  import: "imports",
  reference: "passes as a value",
  name_match: "may call",
  dynamic_import: "may import",
};

// Module bodies appear in paths as "import <module>": importing a module runs its body.
const MODULE = "import ";

const COL = 192;
const NODE_W = 164;
const NODE_H = 46;
const ROW = 64;
const TOP = 40;

/** Last two dotted segments, so a column stays narrow but still says where the code lives. */
function shortName(symbol: string): string {
  const parts = symbol.split(".");
  const tail = parts.slice(-2).join(".");
  return tail.length > 24 ? `…${tail.slice(-23)}` : tail;
}

/** Longest-path layering over the union of the given paths: every edge points right, and the
 * vulnerable symbols share the last column so the eye ends where the risk is. */
function layout(paths: TracePath[]) {
  const nodes = new Map<string, Node>();
  const edges = new Map<string, Edge>();

  paths.forEach((path, p) => {
    path.steps.forEach((step, i) => {
      const node = nodes.get(step.symbol) ?? {
        id: step.symbol,
        pkg: step.package,
        file: step.file,
        line: step.line,
        depth: 0,
        row: 0,
        terminal: false,
        entry: null,
        paths: new Set<number>(),
      };
      node.paths.add(p);
      if (i === 0) node.entry = path.entrypoint_kind;
      if (i === path.steps.length - 1) node.terminal = true;
      nodes.set(step.symbol, node);
      const next = path.steps[i + 1];
      if (next) {
        const key = `${step.symbol}->${next.symbol}`;
        const edge = edges.get(key) ?? { from: step.symbol, to: next.symbol, kind: step.call?.edge ?? "call", paths: new Set<number>() };
        edge.paths.add(p);
        edges.set(key, edge);
      }
    });
  });

  // Relax depths along edges; bounded so a cycle in the data can never hang the page.
  for (let pass = 0; pass < nodes.size; pass++) {
    let changed = false;
    for (const edge of edges.values()) {
      const from = nodes.get(edge.from)!;
      const to = nodes.get(edge.to)!;
      if (to.depth < from.depth + 1) {
        to.depth = from.depth + 1;
        changed = true;
      }
    }
    if (!changed) break;
  }
  // Sinks (vulnerable symbols nothing else calls) move to the last column so the eye ends where
  // the risk is. A vulnerable symbol that other paths continue through keeps its depth.
  const last = Math.max(...[...nodes.values()].map((n) => n.depth));
  const sources = new Set([...edges.values()].map((e) => e.from));
  for (const node of nodes.values()) if (node.terminal && !sources.has(node.id)) node.depth = last;

  const columns: Node[][] = Array.from({ length: last + 1 }, () => []);
  for (const node of nodes.values()) columns[node.depth].push(node);
  const rows = Math.max(...columns.map((c) => c.length));
  columns.forEach((column) => column.forEach((node, i) => (node.row = i + (rows - column.length) / 2)));

  // Column captions: consecutive columns in the same place share one bracketed caption.
  const zone = (column: Node[]) => {
    const pkgs = [...new Set(column.map((n) => n.pkg ?? ""))];
    if (pkgs.length === 1) return pkgs[0] ? `inside ${pkgs[0]}` : "your code";
    return pkgs.includes("") ? "your code and dependencies" : `inside ${pkgs.filter(Boolean).join(", ")}`;
  };
  const captions: { label: string; from: number; to: number }[] = [];
  columns.forEach((column, i) => {
    const label = zone(column);
    const previous = captions[captions.length - 1];
    if (previous && previous.label === label) previous.to = i;
    else captions.push({ label, from: i, to: i });
  });

  return { nodes: [...nodes.values()], edges: [...edges.values()], columns: last + 1, rows, captions };
}

const position = (node: Node) => ({ x: node.depth * COL, y: TOP + node.row * ROW });

/**
 * The reachability trace as a graph: the top paths of a finding merged into one picture, laid out
 * left to right by call depth. Solid edges are statically resolved calls; dashed edges are the
 * over-approximations that can only ever produce "needs review". Hovering or focusing a node
 * isolates the paths that pass through it.
 */
export function TraceGraph({ paths, verdict, caption }: { paths: TracePath[]; verdict: string | null; caption?: string }) {
  const graph = useMemo(() => layout(paths.slice(0, 4)), [paths]);
  const [focus, setFocus] = useState<string | null>(null);
  if (graph.nodes.length === 0) return null;

  const active = focus ? graph.nodes.find((n) => n.id === focus)?.paths ?? null : null;
  const lit = (set: Set<number>) => !active || [...set].some((p) => active.has(p));
  const width = (graph.columns - 1) * COL + NODE_W + 8;
  const height = TOP + graph.rows * ROW;
  const hot = verdict === "reachable";
  const primary = paths[0]?.steps.map((s) => s.symbol).join(" → ") ?? "";

  return (
    <figure className="overflow-x-auto">
      <svg
        viewBox={`-4 0 ${width} ${height}`}
        width={width}
        height={height}
        className="mx-auto block max-w-none"
        role="img"
        aria-label={`Call graph with ${graph.nodes.length} functions over ${paths.length} path${paths.length === 1 ? "" : "s"}. Primary path: ${primary}`}
      >
        {graph.captions.map((c) => {
          const x1 = c.from * COL;
          const x2 = c.to * COL + NODE_W;
          return (
            <g key={`${c.label}-${c.from}`} className="text-muted">
              <path d={`M${x1} 22 V16 H${x2} V22`} fill="none" stroke="currentColor" strokeOpacity={0.45} />
              <text x={x1} y={10} fontSize={11} fill="currentColor">{c.label}</text>
            </g>
          );
        })}

        {graph.edges.map((edge, i) => {
          const from = graph.nodes.find((n) => n.id === edge.from)!;
          const to = graph.nodes.find((n) => n.id === edge.to)!;
          const a = position(from);
          const b = position(to);
          const x1 = a.x + NODE_W;
          const y1 = a.y + NODE_H / 2;
          const x2 = b.x;
          const y2 = b.y + NODE_H / 2;
          const mid = (x1 + x2) / 2;
          const strong = STRONG.has(edge.kind);
          const onPrimary = edge.paths.has(0);
          const stroke = !strong ? "var(--review)" : onPrimary && hot ? "var(--reach)" : "var(--muted)";
          return (
            <g key={`${edge.from}-${edge.to}`} opacity={lit(edge.paths) ? 1 : 0.15} className="transition-opacity duration-200">
              <path
                d={`M${x1} ${y1} C${mid} ${y1}, ${mid} ${y2}, ${x2 - 6} ${y2}`}
                fill="none"
                stroke={stroke}
                strokeWidth={onPrimary ? 1.75 : 1.25}
                strokeDasharray={strong ? undefined : "4 4"}
                pathLength={strong ? 1 : undefined}
                className={strong ? "trace-draw" : "trace-fade"}
                style={{ animationDelay: `${120 + from.depth * 160 + i * 20}ms` }}
              />
              <path d={`M${x2 - 7} ${y2 - 4} L${x2} ${y2} L${x2 - 7} ${y2 + 4}`} fill="none" stroke={stroke} strokeWidth={1.25} />
              <title>{`${edge.from} ${EDGE_WORD[edge.kind] ?? edge.kind} ${edge.to}`}</title>
            </g>
          );
        })}

        {graph.nodes.map((node) => {
          const { x, y } = position(node);
          const vulnerable = node.terminal;
          const app = !node.pkg;
          const isModule = node.id.startsWith(MODULE);
          return (
            <g
              key={node.id}
              transform={`translate(${x} ${y})`}
              opacity={lit(node.paths) ? 1 : 0.25}
              className="cursor-default outline-none transition-opacity duration-200 [&:focus-visible>rect]:stroke-[var(--focus)]"
              tabIndex={0}
              onMouseEnter={() => setFocus(node.id)}
              onMouseLeave={() => setFocus(null)}
              onFocus={() => setFocus(node.id)}
              onBlur={() => setFocus(null)}
            >
              <title>{`${node.id}\n${node.file}:${node.line}${vulnerable ? "\nvulnerable symbol" : ""}`}</title>
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={7}
                fill={app ? "var(--raised)" : "var(--surface)"}
                stroke={vulnerable ? (hot ? "var(--reach)" : "var(--review)") : app ? "var(--muted)" : "var(--line)"}
                strokeWidth={vulnerable ? 1.75 : 1}
                strokeDasharray={app || vulnerable ? undefined : "2 3"}
              />
              {vulnerable && <circle cx={NODE_W - 12} cy={12} r={3.5} fill={hot ? "var(--reach)" : "var(--review)"} />}
              <text x={12} y={19} fontSize={12.5} fontFamily="var(--font-mono)" fill={vulnerable && hot ? "var(--reach)" : "var(--text)"}>
                {shortName(isModule ? node.id.slice(MODULE.length) : node.id)}
              </text>
              <text x={12} y={35} fontSize={10.5} fill="var(--muted)">
                {node.entry
                  ? ENTRYPOINT[node.entry] ?? node.entry
                  : vulnerable
                    ? "vulnerable symbol"
                    : isModule
                      ? "module import"
                      : `${node.file.split("/").pop()}:${node.line}`}
              </text>
            </g>
          );
        })}
      </svg>
      <figcaption className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted">
        {caption && <span className="basis-full text-sm">{caption}</span>}
        <span><Swatch solid /> resolved call</span>
        <span><Swatch /> unresolved, can only mean &ldquo;needs review&rdquo;</span>
        <span>solid boxes are your code, dotted boxes are inside a dependency, a dot marks a vulnerable function</span>
      </figcaption>
    </figure>
  );
}

function Swatch({ solid = false }: { solid?: boolean }) {
  return (
    <svg width="22" height="6" aria-hidden className="mr-1 inline-block align-middle">
      <line x1="0" y1="3" x2="22" y2="3" stroke={solid ? "var(--muted)" : "var(--review)"} strokeWidth="1.5" strokeDasharray={solid ? undefined : "4 3"} />
    </svg>
  );
}
