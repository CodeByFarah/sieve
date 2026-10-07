import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto max-w-xl px-6 py-32">
      <h1 className="text-2xl font-semibold tracking-tight">Nothing here.</h1>
      <p className="mt-3 text-muted">
        This page doesn&apos;t exist, or it belongs to an organization you aren&apos;t a member of. Sieve shows both the same way so
        it never reveals what other organizations contain.
      </p>
      <p className="mt-8 flex gap-6 text-sm">
        <Link href="/app" className="underline underline-offset-4">Go to your organizations</Link>
        <Link href="/" className="underline underline-offset-4">Back to the start</Link>
      </p>
    </main>
  );
}
