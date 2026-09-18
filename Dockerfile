# Multi-stage build for the workspace-bound OPE instance.
#
# Stage "web" builds the founder UI bundle. Stage "go" compiles the
# binary with the bundle embedded (the embedweb tag). The runtime stage
# is a minimal non-root image with a read-only root filesystem and a
# dedicated owner-only data volume.

# ---- Web UI ----
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable pnpm && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

# ---- Go binary ----
FROM golang:1.26-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN GOSUMDB=off go mod download
COPY . ./
COPY --from=web /src/web/dist ./web/dist
RUN GOSUMDB=off CGO_ENABLED=0 go build -tags embedweb -trimpath \
    -o /out/authscope-ope ./cmd/authscope-ope

# ---- Runtime ----
FROM alpine:3.21
RUN adduser -D -u 10001 -h /home/ope ope \
    && mkdir -p /data /app/contracts \
    && chown 10001:10001 /data /app/contracts \
    && chmod 700 /data
COPY --from=go /out/authscope-ope /usr/local/bin/authscope-ope
# The contract lock, capability manifest, and signing-key pins are read
# from disk at runtime via OPE_ROOT.
COPY --chown=10001:10001 contracts/ /app/contracts/
USER 10001:10001
ENV OPE_ROOT=/app \
    OPE_DATA_DIR=/data \
    OPE_MODE=release
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz | grep -q '"status":"ok"'
ENTRYPOINT ["authscope-ope"]
CMD ["serve"]
