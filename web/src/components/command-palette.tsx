"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

type Item = { label: string; hint: string; href: string };

/** ⌘K / Ctrl+K: jump to pages, or search findings, repositories and packages. */
export function CommandPalette({ org }: { org: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<{ query: string; items: Item[] }>({ query: "", items: [] });
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  const pages: Item[] = [
    { label: "Overview", hint: "Page", href: `/app/${org}` },
    { label: "Findings", hint: "Page", href: `/app/${org}/findings` },
    { label: "Reachable findings", hint: "Filter", href: `/app/${org}/findings?verdict=reachable` },
    { label: "Known exploited", hint: "Filter", href: `/app/${org}/findings?kev=true` },
    { label: "Repositories", hint: "Page", href: `/app/${org}/repositories` },
    { label: "Policy", hint: "Page", href: `/app/${org}/policy` },
    { label: "VEX documents", hint: "Page", href: `/app/${org}/vex` },
    { label: "Activity", hint: "Page", href: `/app/${org}/activity` },
  ];

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((value) => !value);
      }
      if (event.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) setTimeout(() => input.current?.focus(), 0);
  }, [open]);

  useEffect(() => {
    const q = query.trim();
    if (!q) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const response = await fetch(`/api/v1/orgs/${org}/search?q=${encodeURIComponent(q)}`, { signal: controller.signal });
        if (!response.ok) return;
        const data = await response.json();
        setResults({ query: q, items: [
          ...data.findings.map((f: { id: string; advisory_id: string; package: string }) => ({
            label: `${f.advisory_id} in ${f.package}`, hint: "Finding", href: `/app/${org}/findings/${f.id}`,
          })),
          ...data.repositories.map((r: { id: string; full_name: string }) => ({
            label: r.full_name, hint: "Repository", href: `/app/${org}/repositories/${r.id}`,
          })),
          ...data.packages.map((p: { name: string; findings: number }) => ({
            label: `${p.name} (${p.findings})`, hint: "Package", href: `/app/${org}/findings?package=${p.name}`,
          })),
        ] });
      } catch {
        /* aborted or offline: keep the previous results */
      }
    }, 150);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query, org]);

  const searched = results.query === query.trim() ? results.items : [];
  const items = [...pages.filter((p) => p.label.toLowerCase().includes(query.toLowerCase())), ...searched];

  function go(item: Item | undefined) {
    if (!item) return;
    setOpen(false);
    setQuery("");
    router.push(item.href);
  }

  return (
    <>
      <button type="button" onClick={() => setOpen(true)}
        className="flex w-full items-center justify-between rounded-md border border-line px-3 py-1.5 text-sm text-muted hover:border-muted">
        Search <kbd className="font-mono text-xs">⌘K</kbd>
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-bg/70 px-4 pt-[15vh] backdrop-blur-sm" onClick={() => setOpen(false)}>
          <div role="dialog" aria-modal="true" aria-label="Search and navigate"
            className="w-full max-w-xl overflow-hidden rounded-lg border border-line bg-surface shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <input
              ref={input}
              name="q"
              type="search"
              value={query}
              onChange={(e) => { setQuery(e.target.value); setActive(0); }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, items.length - 1)); }
                if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
                if (e.key === "Enter") go(items[active]);
              }}
              placeholder="Search advisories, packages, repositories…"
              className="w-full border-b border-line bg-transparent px-4 py-3 outline-none"
              role="combobox" aria-expanded="true" aria-controls="palette-results"
            />
            <ul id="palette-results" role="listbox" className="max-h-80 overflow-y-auto py-1">
              {items.map((item, index) => (
                <li key={`${item.href}-${index}`} role="option" aria-selected={index === active}>
                  <button type="button" onMouseEnter={() => setActive(index)} onClick={() => go(item)}
                    className={`flex w-full justify-between px-4 py-2 text-left text-sm ${index === active ? "bg-raised" : ""}`}>
                    <span>{item.label}</span><span className="text-muted">{item.hint}</span>
                  </button>
                </li>
              ))}
              {items.length === 0 && <li className="px-4 py-3 text-sm text-muted">Nothing matches “{query}”.</li>}
            </ul>
          </div>
        </div>
      )}
    </>
  );
}
