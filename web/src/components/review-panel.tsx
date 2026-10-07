"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { send, type ApiFailure } from "@/lib/client";
import { VERDICT_LABEL, type Verdict } from "@/lib/format";

const STATUS_FOR: Record<Verdict, { value: string; label: string }[]> = {
  reachable: [
    { value: "affected", label: "Affected" },
    { value: "under_investigation", label: "Under investigation" },
    { value: "fixed", label: "Fixed" },
  ],
  not_reached: [
    { value: "not_affected", label: "Not affected" },
    { value: "fixed", label: "Fixed" },
  ],
  needs_review: [
    { value: "under_investigation", label: "Under investigation" },
    { value: "affected", label: "Affected" },
    { value: "fixed", label: "Fixed" },
  ],
};

const JUSTIFICATIONS = [
  ["vulnerable_code_not_in_execute_path", "Vulnerable code is not in an execution path"],
  ["vulnerable_code_not_present", "Vulnerable code is not present"],
  ["component_not_present", "Component is not present"],
  ["vulnerable_code_cannot_be_controlled_by_adversary", "Attacker cannot control the input"],
  ["inline_mitigations_already_exist", "Mitigations already exist"],
] as const;

export function ReviewPanel({ findingId, version, analysedVerdict }: { findingId: string; version: number; analysedVerdict: Verdict }) {
  const router = useRouter();
  const [verdict, setVerdict] = useState<Verdict>(analysedVerdict);
  const [status, setStatus] = useState(STATUS_FOR[analysedVerdict][0].value);
  const [justification, setJustification] = useState<string>(JUSTIFICATIONS[0][0]);
  const [comment, setComment] = useState("");
  const [error, setError] = useState<ApiFailure | null>(null);
  const [saving, setSaving] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await send("POST", `/api/v1/findings/${findingId}/reviews`, {
        expected_version: version,
        decided_verdict: verdict,
        vex_status: status,
        justification: status === "not_affected" ? justification : null,
        comment: comment || null,
      });
      router.refresh();
    } catch (failure) {
      setError(failure as ApiFailure);
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <fieldset>
        <legend className="text-sm text-muted">Your conclusion</legend>
        <div className="mt-2 flex flex-wrap gap-2">
          {(Object.keys(VERDICT_LABEL) as Verdict[]).map((value) => (
            <label key={value} className={`cursor-pointer rounded-md border px-3 py-1.5 text-sm ${verdict === value ? "border-text" : "border-line text-muted"}`}>
              <input type="radio" name="verdict" value={value} checked={verdict === value} className="sr-only"
                onChange={() => { setVerdict(value); setStatus(STATUS_FOR[value][0].value); }} />
              {VERDICT_LABEL[value]}{value === analysedVerdict ? " (Sieve)" : ""}
            </label>
          ))}
        </div>
      </fieldset>
      <label className="block text-sm">
        <span className="text-muted">VEX status</span>
        <select value={status} onChange={(e) => setStatus(e.target.value)} className="mt-1 block w-full rounded-md border border-line bg-surface px-3 py-2">
          {STATUS_FOR[verdict].map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
      </label>
      {status === "not_affected" && (
        <label className="block text-sm">
          <span className="text-muted">Justification</span>
          <select value={justification} onChange={(e) => setJustification(e.target.value)} className="mt-1 block w-full rounded-md border border-line bg-surface px-3 py-2">
            {JUSTIFICATIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>
      )}
      <label className="block text-sm">
        <span className="text-muted">Reasoning (kept in the audit log)</span>
        <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={3} maxLength={4000}
          className="mt-1 block w-full rounded-md border border-line bg-surface px-3 py-2" />
      </label>
      {error && (
        <p role="alert" className="text-sm text-reach">
          {error.code === "conflict" ? "Someone changed this finding since you opened it. Reload to see their decision." : error.message}
        </p>
      )}
      <button type="submit" disabled={saving} className="rounded-md bg-text px-4 py-2 text-sm font-medium text-bg disabled:opacity-50">
        {saving ? "Recording…" : "Record decision"}
      </button>
    </form>
  );
}
