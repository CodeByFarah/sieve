"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { send, type ApiFailure } from "@/lib/client";

/** Starts (or joins) a real scan of the sample application and opens its live progress. */
export function DemoRunButton({ label = "Run the live demo" }: { label?: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const result = await send<{ scan: { id: string } }>("POST", "/api/v1/demo/scans");
      router.push(`/app/sieve-demo/scans/${result.scan.id}`);
    } catch (failure) {
      const { code, message } = failure as ApiFailure;
      setError(code === "rate_limited" ? "The demo was run many times from your network recently. The latest results are below." : message);
      setBusy(false);
    }
  }

  return (
    <div>
      <button type="button" onClick={run} disabled={busy}
        className="rounded-md bg-text px-5 py-2.5 font-medium text-bg transition hover:opacity-90 disabled:opacity-60">
        {busy ? "Starting the scan…" : label}
      </button>
      {error && <p role="alert" className="mt-2 max-w-sm text-sm text-muted">{error}</p>}
    </div>
  );
}
