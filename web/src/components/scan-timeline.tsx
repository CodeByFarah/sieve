import { STAGE_LABEL, STAGE_ORDER } from "@/lib/format";

type StageProgress = {
  status?: string;
  started_at?: string;
  finished_at?: string;
  duration_seconds?: number;
  counts?: Record<string, unknown>;
};

function countsText(counts: Record<string, unknown> | undefined): string {
  if (!counts) return "";
  return Object.entries(counts)
    .filter(([, v]) => typeof v === "number" && v > 0)
    .slice(0, 2)
    .map(([k, v]) => {
      const noun = k.replaceAll("_", " ");
      return `${(v as number).toLocaleString("en")} ${v === 1 && noun.endsWith("s") ? noun.slice(0, -1) : noun}`;
    })
    .join(", ");
}

const seconds = (s: number) => (s < 1 ? `${Math.round(s * 1000)} ms` : `${s.toFixed(1)} s`);

/**
 * A Gantt chart of one real scan, read from the timings the pipeline persists for every stage.
 * The longest stage is drawn in full ink: that is where the next optimisation should go.
 */
export function ScanTimeline({ progress, startedAt, finishedAt }: {
  progress: Record<string, StageProgress>;
  startedAt: string;
  finishedAt: string;
}) {
  const t0 = new Date(startedAt).getTime();
  const total = Math.max((new Date(finishedAt).getTime() - t0) / 1000, 0.001);
  const stages = STAGE_ORDER.filter((name) => progress[name]?.started_at && progress[name]?.duration_seconds !== undefined).map((name) => {
    const p = progress[name];
    const offset = (new Date(p.started_at!).getTime() - t0) / 1000;
    return { name, offset, duration: p.duration_seconds!, counts: countsText(p.counts) };
  });
  if (stages.length === 0) return null;
  const longest = stages.reduce((a, b) => (b.duration > a.duration ? b : a));
  const ticks = [0, total / 2, total];

  return (
    <figure>
      <div className="grid grid-cols-[minmax(7rem,15rem)_minmax(0,1fr)_4rem] items-center gap-x-4 gap-y-1.5 text-sm">
        {stages.map((s) => {
          const left = (s.offset / total) * 100;
          const width = Math.max((s.duration / total) * 100, 0.4);
          const lead = s === longest;
          return (
            <div key={s.name} className="contents">
              <span className={lead ? "text-text" : "text-muted"}>{STAGE_LABEL[s.name] ?? s.name}</span>
              <div className="relative h-5" title={s.counts || undefined}>
                <div className="absolute inset-y-[9px] left-0 right-0 bg-line/40" aria-hidden />
                <div
                  className={`absolute inset-y-1 rounded-sm ${lead ? "bg-text" : "bg-muted/70"}`}
                  style={{ left: `${left}%`, width: `${width}%` }}
                />
                {s.counts && (
                  <span
                    className="absolute top-1/2 hidden -translate-y-1/2 whitespace-nowrap pl-2 text-xs text-muted sm:block"
                    style={left + width > 70 ? { right: `${100 - left + 1}%` } : { left: `${left + width}%` }}
                  >
                    {s.counts}
                  </span>
                )}
              </div>
              <span className={`text-right tabular-nums ${lead ? "text-text" : "text-muted"}`}>{seconds(s.duration)}</span>
            </div>
          );
        })}
        <span />
        <div className="relative mt-1 h-4 border-t border-line text-xs text-muted">
          {ticks.map((t, i) => (
            <span key={i} className="absolute top-1 tabular-nums" style={i === 0 ? { left: 0 } : i === 2 ? { right: 0 } : { left: "50%", transform: "translateX(-50%)" }}>
              {seconds(t)}
            </span>
          ))}
        </div>
        <span />
      </div>
      <figcaption className="mt-4 text-xs text-muted">
        Recorded by the pipeline for this scan: {seconds(total)} from first stage to last.{" "}
        {(STAGE_LABEL[longest.name] ?? longest.name).replace(/^./, (c) => c.toUpperCase())} took longest
        ({Math.round((longest.duration / total) * 100)}%)
        {longest.name === "callgraph" ? ", because every dependency on the path is parsed from its published source." : "."}
      </figcaption>
    </figure>
  );
}
