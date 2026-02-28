# ============================================================
# Agent-WatchDog — Multi-stage Docker build
#
# Usage:
#   docker build -t agent-watchdog .
#   docker run --privileged \
#     -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
#     -v /proc:/host/proc:ro \
#     -p 3000:3000 -p 5173:5173 \
#     agent-watchdog
#
# The container MUST run with --privileged (or at least
# CAP_BPF + CAP_SYS_ADMIN) to load eBPF programs.
# ============================================================

# ── Stage 1: Build eBPF program ───────────────────────────────
FROM rust:latest AS ebpf-builder

# Install nightly + bpf-linker
RUN rustup toolchain install nightly --component rust-src \
    && cargo +nightly install bpf-linker

WORKDIR /build

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY agent-watchdog-common/Cargo.toml agent-watchdog-common/Cargo.toml
COPY agent-watchdog-ebpf/Cargo.toml agent-watchdog-ebpf/Cargo.toml
COPY agent-watchdog-ebpf/rust-toolchain.toml agent-watchdog-ebpf/rust-toolchain.toml
COPY agent-watchdog/Cargo.toml agent-watchdog/Cargo.toml
COPY xtask/Cargo.toml xtask/Cargo.toml

# Copy source
COPY agent-watchdog-common/src agent-watchdog-common/src
COPY agent-watchdog-ebpf/src agent-watchdog-ebpf/src

# Build eBPF (must target x86_64 for the runtime host)
RUN cd agent-watchdog-ebpf \
    && CARGO_ENCODED_RUSTFLAGS='--cfg=bpf_target_arch="x86_64"' \
    cargo +nightly build \
    --target=bpfel-unknown-none \
    -Z build-std=core \
    --release

# ── Stage 2: Build user-space Rust daemon ─────────────────────
FROM rust:latest AS rust-builder

WORKDIR /build

# Copy manifests for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY agent-watchdog-common/Cargo.toml agent-watchdog-common/Cargo.toml
COPY agent-watchdog/Cargo.toml agent-watchdog/Cargo.toml
COPY xtask/Cargo.toml xtask/Cargo.toml

# Create stub files so cargo can resolve the workspace
RUN mkdir -p agent-watchdog-common/src \
    && echo '#![no_std]' > agent-watchdog-common/src/lib.rs \
    && mkdir -p agent-watchdog/src \
    && echo 'fn main() {}' > agent-watchdog/src/main.rs \
    && mkdir -p xtask/src \
    && echo 'fn main() {}' > xtask/src/main.rs

# Pre-build dependencies (cached unless Cargo.toml changes)
RUN cargo build --release --package agent-watchdog 2>/dev/null || true

# Copy real source
COPY agent-watchdog-common/src agent-watchdog-common/src
COPY agent-watchdog/src agent-watchdog/src
COPY xtask/src xtask/src

# Rebuild with real source
RUN touch agent-watchdog-common/src/lib.rs agent-watchdog/src/main.rs \
    && cargo build --release --package agent-watchdog

# ── Stage 3: Build React dashboard ───────────────────────────
FROM oven/bun:1 AS dashboard-builder

WORKDIR /build/dashboard

# Copy package manifests for dependency caching
COPY dashboard/package.json dashboard/bun.lock* ./

RUN bun install --frozen-lockfile || bun install

# Copy source and build
COPY dashboard/ .

RUN bun run build

# ── Stage 4: Runtime image ────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agent-watchdog

# Copy eBPF binary
COPY --from=ebpf-builder \
    /build/agent-watchdog-ebpf/target/bpfel-unknown-none/release/agent-watchdog \
    ./target/bpfel-unknown-none/release/agent-watchdog

# Copy user-space binary
COPY --from=rust-builder \
    /build/target/release/agent-watchdog \
    ./agent-watchdog

# Copy dashboard static files
COPY --from=dashboard-builder \
    /build/dashboard/dist \
    ./dashboard/dist

# Copy default config
COPY watchdog.toml ./watchdog.toml

ENV RUST_LOG=info

EXPOSE 3000

# The entrypoint loads eBPF and starts the API server.
# --privileged is required at `docker run` time.
ENTRYPOINT ["./agent-watchdog", \
    "--bpf-path", "target/bpfel-unknown-none/release/agent-watchdog", \
    "--config", "watchdog.toml"]
