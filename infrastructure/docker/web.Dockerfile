# Next.js frontend, built as a standalone server. Build context: repository root.
FROM node:26-alpine AS deps
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci

FROM node:26-alpine AS build
WORKDIR /web
# Rewrites (/api -> API) are resolved at build time, so the API origin is a build argument.
ARG SIEVE_API_URL=http://api:8000
ENV SIEVE_API_URL=${SIEVE_API_URL} NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /web/node_modules ./node_modules
COPY web/ ./
RUN npm run build

FROM node:26-alpine AS runtime
WORKDIR /web
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S -g 10001 sieve && adduser -S -u 10001 -G sieve sieve
COPY --from=build --chown=sieve:sieve /web/.next/standalone ./
COPY --from=build --chown=sieve:sieve /web/.next/static ./.next/static
COPY --from=build --chown=sieve:sieve /web/public ./public
# Writable paths for a read-only root filesystem (seeded into ECS scratch volumes, ownership included).
RUN mkdir -p /web/.next/cache /scratch/tmp && chown -R sieve:sieve /web/.next/cache /scratch
VOLUME ["/web/.next/cache", "/scratch"]
ENV TMPDIR=/scratch/tmp
USER sieve
EXPOSE 3000
CMD ["node", "server.js"]
