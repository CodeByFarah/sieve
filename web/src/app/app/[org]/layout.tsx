import { AppShell } from "@/components/app-shell";
import { tryApi, type Me } from "@/lib/api";

export default async function OrgLayout({ children, params }: { children: React.ReactNode; params: Promise<{ org: string }> }) {
  const { org } = await params;
  const me = await tryApi<Me>("/api/v1/me");
  return (
    <AppShell org={org} me={me}>
      {children}
    </AppShell>
  );
}
