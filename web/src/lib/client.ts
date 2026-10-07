/** Browser-side calls. State-changing requests echo the CSRF cookie in a header. */

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|; )sieve_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

export type ApiFailure = { code: string; message: string; correlationId: string | null };

export async function send<T>(method: "POST" | "PUT", path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "content-type": "application/json", "X-Sieve-CSRF": csrfToken() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const failure: ApiFailure = {
      code: data?.error?.code ?? "http_error",
      message: data?.error?.message ?? `Request failed (${response.status}).`,
      correlationId: data?.error?.correlation_id ?? response.headers.get("x-correlation-id"),
    };
    throw failure;
  }
  return data as T;
}
