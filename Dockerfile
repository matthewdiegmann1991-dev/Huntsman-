# Current Huntsman Recon image for self-hosted Linux container runtimes.
# This is the single canonical container definition for Huntsman Recon.
# Base images are pinned by digest, so a moved tag cannot change the toolchain or OS under a build.
FROM rust:1.99-trixie@sha256:6ff07edce8775d0f64be7aba9197229407301bddf2054d62c27b541a6238a181 AS builder
WORKDIR /build

# Dependencies first, in a layer keyed on the manifests alone: a rebuild after a source change
# (every deploy of a new commit) reuses the compiled dependencies instead of compiling the whole
# graph again. Stub targets let Cargo load the workspace (xtask is a member, so it needs a target)
# and build huntsman-recon's dependencies; the stubs are deleted before the real sources arrive.
COPY Cargo.toml Cargo.lock ./
COPY xtask/Cargo.toml ./xtask/Cargo.toml
RUN mkdir -p src xtask/src \
    && printf 'fn main() {}\n' > src/main.rs \
    && : > src/lib.rs \
    && printf 'fn main() {}\n' > xtask/src/main.rs \
    && cargo build --release --locked --bin huntsman-recon \
    && rm -rf src xtask/src

# Declared after the dependency layer: a build argument invalidates the cache of every step after
# its declaration, and the source SHA changes with every commit.
# An explicit SHA wins; otherwise a configured, provider-neutral source SHA identifies it.
# A manual/image build without either value stays "unknown" and fails exact-SHA acceptance.
ARG HUNTSMAN_BUILD_SHA=unknown
ARG HUNTSMAN_SOURCE_SHA
ENV HUNTSMAN_BUILD_SHA=${HUNTSMAN_BUILD_SHA}

COPY capabilities.json benchmarks.json HUNTSMAN_CANONICAL_TEAM_DIRECTIVE.md ./
COPY src ./src
# The root manifest declares xtask as a workspace member, so cargo reads its manifest and
# source while loading the workspace. This build does not compile xtask.
COPY xtask/src ./xtask/src

# The crate's own artifacts from the stub build are removed, so its real sources are compiled
# whatever their timestamps: COPY keeps the checkout's times, which can be older than the stubs.
RUN if [ "$HUNTSMAN_BUILD_SHA" = "unknown" ] && [ -n "${HUNTSMAN_SOURCE_SHA:-}" ]; then \
      export HUNTSMAN_BUILD_SHA="$HUNTSMAN_SOURCE_SHA"; \
    fi; \
    cargo clean --release --package huntsman-recon \
    && cargo build --release --locked --bin huntsman-recon

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --home-dir /data --shell /usr/sbin/nologin huntsman \
    && mkdir -p /data/.huntsman /data/var \
    && chown -R huntsman:huntsman /data

COPY --from=builder /build/target/release/huntsman-recon /usr/local/bin/huntsman-recon
COPY scripts/container-entrypoint.sh /usr/local/bin/huntsman-entrypoint
RUN chmod 0755 /usr/local/bin/huntsman-recon /usr/local/bin/huntsman-entrypoint

ENV HOME=/data \
    HUNTSMAN_DATA_DIR=/data \
    HUNTSMAN_STARTUP_CHECK=1

WORKDIR /data
EXPOSE 8080
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8080}/api/health" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/huntsman-entrypoint"]
CMD ["serve"]
