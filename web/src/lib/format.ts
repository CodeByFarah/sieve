export type Verdict = "reachable" | "not_reached" | "needs_review";

export const VERDICT_LABEL: Record<Verdict, string> = {
  reachable: "Reachable",
  not_reached: "Not reached",
  needs_review: "Needs review",
};

export const VERDICT_TEXT: Record<Verdict, string> = {
  reachable: "text-reach",
  not_reached: "text-clear",
  needs_review: "text-review",
};

export const VERDICT_BG: Record<Verdict, string> = {
  reachable: "bg-reach",
  not_reached: "bg-clear",
  needs_review: "bg-review",
};

export const REASONS: Record<string, string> = {
  path_found: "Static call path found",
  package_not_imported: "Package never imported",
  no_path: "No path to the vulnerable code",
  version_unpinned: "Version not pinned",
  package_source_unavailable: "Package source unavailable",
  incomplete_import_graph: "Some imports could not be analysed",
  no_verified_symbols: "No known vulnerable function",
  reference_only: "Referenced, never called directly",
  dynamic_dispatch: "Only through calls with unknown targets",
  dynamic_import: "Only through imports by computed name",
  dynamic_attribute: "Attributes looked up by computed name",
  parse_failure: "Some source could not be parsed",
  budget_exceeded: "Analysis hit its resource limits",
};

export const ENTRYPOINT: Record<string, string> = {
  http_route: "HTTP route",
  cli_command: "CLI command",
  task: "Background task",
  main: "Script entry point",
  app_function: "Application function",
  module_import: "Module import",
};

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const units: [number, string][] = [
    [60, "minute"],
    [3600, "hour"],
    [86400, "day"],
    [604800, "week"],
  ];
  let [size, unit] = units[0];
  for (const candidate of units) if (seconds >= candidate[0]) [size, unit] = candidate;
  const value = Math.floor(seconds / size);
  return `${value} ${unit}${value === 1 ? "" : "s"} ago`;
}

export function shortSha(sha: string): string {
  return sha.slice(0, 7);
}

export function percent(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${Math.round(Number(value) * 100)}%`;
}
