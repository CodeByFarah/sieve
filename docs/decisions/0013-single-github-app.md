# ADR-0013: One GitHub App for login and repository access

- Status: Accepted
- Date: 2026-10-06

## Problem

Users must log in with GitHub, and Sieve needs read access to selected repositories plus permission
to create check runs.

## Alternatives

- **OAuth App for login + GitHub App for access** — two registrations, two secret sets, two
  permission models to explain.
- **OAuth App only** with `repo` scope — broad access to *all* the user's repositories, long-lived user
  tokens, no check runs as an app identity.
- **Single GitHub App** using user-to-server authorisation for login and installation tokens for repo
  access — chosen.

## Decision

One GitHub App with minimum permissions: `contents: read`, `metadata: read`, `pull_requests: read`,
`checks: write`; webhook events `installation`, `installation_repositories`, `push`, `pull_request`.
User login uses the App's OAuth flow only to identify the user and their installations; the user
access token is used once at login and not stored.

## Trade-offs

GitHub App user tokens expire (8h by default) — irrelevant because Sieve doesn't keep them.

## 10× scale

Installation tokens are cached per installation until shortly before expiry; GitHub's rate limits are
per installation, which naturally partitions load.

## Enterprise

GitHub Enterprise Server support needs a configurable API base URL — designed in from the start
(`GITHUB_API_URL` setting).
