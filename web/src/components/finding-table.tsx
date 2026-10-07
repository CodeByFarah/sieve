import Link from "next/link";
import { Kev, Severity, VerdictMark } from "./ui";
import { relativeTime, type Verdict } from "@/lib/format";
import type { FindingItem } from "@/lib/api";

export function FindingTable({ org, items }: { org: string; items: FindingItem[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-line text-left text-muted">
            <th className="py-2 pr-4 font-normal">Reachability</th>
            <th className="py-2 pr-4 font-normal">Vulnerability</th>
            <th className="py-2 pr-4 font-normal">Package</th>
            <th className="py-2 pr-4 font-normal">Severity</th>
            <th className="py-2 pr-4 text-right font-normal">Risk</th>
            <th className="py-2 pr-4 font-normal">Repository</th>
            <th className="py-2 font-normal">Discovered</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id} className="group border-b border-line/60 hover:bg-raised/50">
              <td className="py-3 pr-4 align-top">
                <VerdictMark verdict={item.effective_verdict as Verdict | null} />
                <span className="block text-xs text-muted">
                  {item.review_state === "accepted" || item.review_state === "overridden"
                    ? "reviewed"
                    : item.confidence ? `${item.confidence} confidence` : ""}
                </span>
              </td>
              <td className="py-3 pr-4 align-top">
                <Link href={`/app/${org}/findings/${item.id}`} className="font-mono group-hover:underline">
                  {item.advisory_id}
                </Link>
                <span className="block max-w-xs truncate text-xs text-muted">{item.summary}</span>
              </td>
              <td className="py-3 pr-4 align-top font-mono">
                {item.package} <span className="text-muted">{item.installed_version ?? "unpinned"}</span>
              </td>
              <td className="py-3 pr-4 align-top">
                <Severity level={item.severity} />
                {item.kev && <span className="mt-1 block"><Kev /></span>}
              </td>
              <td className="py-3 pr-4 text-right align-top tabular-nums">{item.risk_score == null ? "—" : Number(item.risk_score).toFixed(0)}</td>
              <td className="py-3 pr-4 align-top text-muted">{item.repository_full_name}</td>
              <td className="py-3 align-top text-muted">{relativeTime(item.first_seen_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
