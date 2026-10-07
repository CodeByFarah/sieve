# ADR-0006: S3 for scan artifacts

- Status: Accepted
- Date: 2026-10-06

## Problem

SBOMs, call-graph snapshots, cached package indexes, evidence bundles and VEX documents are large,
immutable, and read rarely. Storing them in Postgres bloats backups and the buffer cache.

## Alternatives

Postgres `bytea`/large objects (simple, but bloats the DB); local disk (not shared between workers);
S3 (chosen).

## Decision

An `ArtifactStore` interface with an S3 implementation (MinIO locally, real S3 in production).
Postgres stores the object key and SHA-256; content is verified on read. Keys are content-addressed
where content is shareable across tenants (package indexes: `pkgindex/{ecosystem}/{name}/{version}/{artifact_sha256}`)
and tenant-prefixed otherwise (`org/{org_id}/scans/{scan_id}/sbom.cdx.json`).

## Trade-offs

Two stores to keep consistent: an artifact is written **before** the row referencing it commits, and
an orphan sweeper deletes unreferenced objects older than a day.

## 10× scale

S3 scales without change; lifecycle rules move old scan artifacts to cheaper storage classes.

## Enterprise

Customer-managed KMS keys per tenant; object lock for VEX documents if required for compliance.
