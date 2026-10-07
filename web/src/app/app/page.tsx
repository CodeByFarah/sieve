import { redirect } from "next/navigation";
import { tryApi, type Me } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function AppIndex() {
  const me = await tryApi<Me>("/api/v1/me");
  const own = me?.organizations.find((o) => o.account_type !== "demo");
  redirect(`/app/${own?.login ?? "sieve-demo"}`);
}
