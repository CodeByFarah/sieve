"use client";

import { ErrorState } from "@/components/ui";

export default function OrgError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="space-y-4">
      <ErrorState
        title="This page couldn't load."
        body="The Sieve API did not answer as expected. Nothing was changed. Try again; if it keeps failing, include the error ID when reporting it."
        correlationId={error.digest}
      />
      <button type="button" onClick={reset} className="rounded-md border border-line px-4 py-2 text-sm">Try again</button>
    </div>
  );
}
