import type { NextConfig } from "next";

const api = process.env.SIEVE_API_URL ?? "http://127.0.0.1:8000";

// The Content-Security-Policy is set per request in src/proxy.ts, because it carries a nonce.
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  // Browsers honour this only over HTTPS, so it is harmless in local development.
  { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const config: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  // The browser talks to one origin; the API is reached through these rewrites, so session
  // cookies stay first-party and SameSite=Lax protects them.
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${api}/api/:path*` },
      { source: "/webhooks/:path*", destination: `${api}/webhooks/:path*` },
    ];
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default config;
