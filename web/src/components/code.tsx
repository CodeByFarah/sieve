/** Read-only code excerpt with a lightweight Python highlighter. Code is rendered as text
 * nodes (never HTML), so repository content cannot inject markup. */

const TOKEN =
  /(#.*$)|("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(@[\w.]+)|\b(def|class|return|import|from|as|if|elif|else|for|while|try|except|finally|with|lambda|yield|raise|in|not|and|or|is|None|True|False|async|await|pass)\b|\b(\d+(?:\.\d+)?)\b/g;

function highlight(line: string): React.ReactNode[] {
  const parts: React.ReactNode[] = [];
  let last = 0;
  for (const match of line.matchAll(TOKEN)) {
    const index = match.index ?? 0;
    if (index > last) parts.push(line.slice(last, index));
    const [text, comment, string, decorator, keyword] = match;
    const style = comment
      ? "text-muted italic"
      : string
        ? "text-clear"
        : decorator
          ? "text-review"
          : keyword
            ? "font-semibold"
            : "text-focus";
    parts.push(
      <span key={index} className={style}>
        {text}
      </span>,
    );
    last = index + text.length;
  }
  if (last < line.length) parts.push(line.slice(last));
  return parts;
}

export type Snippet = { start: number; highlight: number; lines: string[] };

export function CodeExcerpt({ file, snippet, note }: { file: string; snippet: Snippet; note?: string }) {
  return (
    <figure className="overflow-hidden rounded-md border border-line bg-surface">
      <figcaption className="flex justify-between gap-4 border-b border-line px-3 py-1.5 font-mono text-xs text-muted">
        <span className="truncate">{file}</span>
        {note && <span className="shrink-0">{note}</span>}
      </figcaption>
      <pre className="overflow-x-auto py-2 font-mono text-[13px] leading-6">
        {snippet.lines.map((line, i) => {
          const number = snippet.start + i;
          const marked = number === snippet.highlight;
          return (
            <div key={number} className={`flex ${marked ? "bg-reach/12" : ""}`}>
              <span aria-hidden className={`w-12 shrink-0 select-none pr-3 text-right ${marked ? "font-semibold text-text" : "text-muted"}`}>
                {number}
              </span>
              <code className={`whitespace-pre pr-4 ${marked ? "border-l-2 border-reach pl-2" : "pl-2.5"}`}>{highlight(line)}</code>
            </div>
          );
        })}
      </pre>
    </figure>
  );
}
