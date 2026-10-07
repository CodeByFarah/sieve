import Link from "next/link";
import { CommandPalette } from "./command-palette";
import { ThemeToggle } from "./theme-toggle";
import { NavLink } from "./nav-link";
import type { Me } from "@/lib/api";

export function AppShell({ org, me, children }: { org: string; me: Me | null; children: React.ReactNode }) {
  const nav = [
    ["Overview", `/app/${org}`],
    ["Findings", `/app/${org}/findings`],
    ["Repositories", `/app/${org}/repositories`],
    ["Policy", `/app/${org}/policy`],
    ["VEX", `/app/${org}/vex`],
    ["Activity", `/app/${org}/activity`],
  ] as const;
  const isDemo = org === "sieve-demo";
  return (
    <div className="grid min-h-screen md:grid-cols-[13.5rem_1fr]">
      <aside className="border-b border-line px-4 py-4 md:sticky md:top-0 md:h-screen md:border-b-0 md:border-r">
        <Link href="/" className="block text-lg font-semibold tracking-tight">Sieve</Link>
        <p className="mt-0.5 truncate text-sm text-muted">{org}</p>
        <div className="mt-5"><CommandPalette org={org} /></div>
        <nav aria-label="Main" className="mt-5 flex gap-1 overflow-x-auto md:flex-col">
          {nav.map(([label, href]) => (
            <NavLink key={href} href={href} exact={label === "Overview"}>{label}</NavLink>
          ))}
        </nav>
        <div className="mt-6 hidden space-y-2 text-sm md:block">
          {me?.user ? (
            <p className="text-muted">Signed in as {me.user.login}</p>
          ) : me?.github_login_enabled ? (
            <a href="/api/v1/auth/github/login" className="text-muted hover:text-text">Sign in with GitHub</a>
          ) : null}
          <ThemeToggle />
        </div>
      </aside>
      <div className="min-w-0">
        {isDemo && (
          <p className="border-b border-line px-6 py-2 text-sm text-muted">
            Public demo: a real scan of a deliberately vulnerable sample app, read-only. Reviews shown were made by the Sieve maintainers.
          </p>
        )}
        <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
      </div>
    </div>
  );
}
