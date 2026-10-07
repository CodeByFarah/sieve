import "server-only";

import { cookies } from "next/headers";
import { notFound } from "next/navigation";
import type { components } from "./api-types";

export type Schemas = components["schemas"];
export type Me = Schemas["MeOut"];
export type Overview = Schemas["OverviewOut"];
export type FindingItem = Schemas["FindingItemOut"];
export type FindingPage = Schemas["FindingPage"];
export type FindingDetail = Schemas["FindingDetailOut"];
export type Repository = Schemas["RepositoryOut"];
export type Scan = Schemas["ScanOut"];
export type ScanDetail = Schemas["ScanDetailOut"];
export type AuditEvent = Schemas["AuditEventOut"];
export type Demo = Schemas["DemoOut"];
export type Policy = Schemas["PolicyOut"];
export type VexDocument = Schemas["VexDocumentOut"];
export type SourceHealth = Schemas["SourceHealthOut"];

const API = process.env.SIEVE_API_URL ?? "http://127.0.0.1:8000";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public correlationId: string | null,
  ) {
    super(message);
  }
}

/** Server-side read from the API, forwarding the visitor's session cookie. */
export async function api<T>(path: string): Promise<T> {
  const jar = await cookies();
  const response = await fetch(`${API}${path}`, {
    headers: { cookie: jar.toString(), accept: "application/json" },
    cache: "no-store",
  });
  // The API answers 404 both for missing records and for other tenants' records; both render as not found.
  if (response.status === 404) notFound();
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(
      response.status,
      body?.error?.code ?? "http_error",
      body?.error?.message ?? `Request failed with ${response.status}`,
      body?.error?.correlation_id ?? response.headers.get("x-correlation-id"),
    );
  }
  return (await response.json()) as T;
}

/** Like `api`, but returns null instead of throwing when the API is unreachable or says no. */
export async function tryApi<T>(path: string): Promise<T | null> {
  try {
    return await api<T>(path);
  } catch {
    return null;
  }
}
