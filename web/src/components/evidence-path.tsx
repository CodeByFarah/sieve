import { CodeExcerpt, type Snippet } from "./code";
import { ENTRYPOINT } from "@/lib/format";

type Step = {
  symbol: string;
  kind: string;
  package: string | null;
  file: string;
  line: number;
  call: { file: string; line: number; edge: string } | null;
  snippet?: Snippet | null;
};

const EDGE: Record<string, string> = {
  call: "calls",
  method: "calls (receiver type inferred)",
  import: "imports",
  reference: "passes as a value",
  name_match: "may call (target not statically known)",
  dynamic_import: "may import by name",
};

/** The signature view: each hop of the call path, application code first, with the exact line
 * that makes the next call. Uncertain hops are drawn dashed and say so in words. */
export function EvidencePath({ steps, entrypoint, vulnerable }: { steps: Step[]; entrypoint: string; vulnerable: boolean }) {
  return (
    <ol className="relative space-y-0" aria-label="Call path from application code to the vulnerable symbol">
      {steps.map((step, index) => {
        const last = index === steps.length - 1;
        const uncertain = step.call && !["call", "import", "method"].includes(step.call.edge);
        return (
          <li key={`${step.symbol}-${index}`} className="grid grid-cols-[1.25rem_1fr] gap-x-4">
            <div className="flex flex-col items-center">
              <span
                aria-hidden
                className={`mt-1.5 h-3 w-3 shrink-0 rounded-full border-2 ${
                  last && vulnerable ? "border-reach bg-reach" : step.package ? "border-muted bg-bg" : "border-text bg-text"
                }`}
              />
              {!last && <span aria-hidden className={`w-px flex-1 ${uncertain ? "border-l border-dashed border-review" : "bg-line"}`} />}
            </div>
            <div className={last ? "pb-1" : "pb-6"}>
              <p className="text-xs text-muted">
                {index === 0 ? ENTRYPOINT[entrypoint] ?? entrypoint : step.package ? `in ${step.package}` : "application code"}
              </p>
              <p className={`font-mono text-sm break-all ${last && vulnerable ? "text-reach" : ""}`}>
                {step.symbol}
                {last && vulnerable && <span className="ml-2 font-sans text-xs">vulnerable symbol</span>}
              </p>
              <p className="font-mono text-xs text-muted">
                {step.file}:{step.call && !step.package ? step.call.line : step.line}
              </p>
              {step.snippet && (
                <div className="mt-2 max-w-3xl">
                  <CodeExcerpt file={step.file} snippet={step.snippet} note={step.package ? "definition" : "call site"} />
                </div>
              )}
              {step.call && (
                <p className={`mt-2 text-xs ${uncertain ? "text-review" : "text-muted"}`}>{EDGE[step.call.edge] ?? step.call.edge} ↓</p>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
