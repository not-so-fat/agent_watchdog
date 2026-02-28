# Agent-WatchDog — Copilot Instructions

> Adapted from [Everything Claude Code](https://github.com/affaan-m/everything-claude-code) best practices.

## Project Overview

Stack: Rust (nightly + stable), eBPF (Aya framework), Linux kernel tracepoints, Tokio async runtime
Architecture: eBPF kernel-space program + user-space daemon communicating via PerfEventArray

## Critical Rules

### Rust Conventions
- Use `thiserror` for library errors, `anyhow` only in binary crates
- No `.unwrap()` or `.expect()` in production code — propagate errors with `?`
- eBPF programs: `#![no_std]`, `#![no_main]`, `panic = "abort"`, `opt-level >= 2`
- eBPF stack limit is 512 bytes — use `PerCpuArray` scratch buffers for large structs
- NEVER dereference user-space pointers in eBPF — always use `bpf_probe_read_user_str_bytes`
- Derive `Debug` on all public types; derive `Clone`, `Copy` only when needed
- No `unsafe` blocks unless justified with a `// SAFETY:` comment

### eBPF-Specific Rules
- The eBPF verifier rejects debug builds — always compile with `--release`
- Shared types (`FileOpenEvent`) must be `#[repr(C)]` with fixed-size fields only
- No heap allocation, no `String`, no `Vec`, no `Option` in shared eBPF types
- Test on real Linux kernel ≥ 5.4 with BTF support — eBPF cannot run on macOS

### Error Handling
- eBPF: return 0 on error, never panic (`unsafe { core::hint::unreachable_unchecked() }`)
- User-space: use `anyhow::Context` for all fallible operations with descriptive messages
- Log errors with `log::warn!` / `log::info!`, never silently swallow

### Security
- NEVER hardcode secrets in source code
- Validate all user input before processing
- Sensitive file keywords list must be comprehensive and lowercase-compared
- eBPF programs run with root privileges — minimize attack surface

### Testing (TDD Workflow)
1. Write test first (RED)
2. Run test — it should FAIL
3. Write minimal implementation (GREEN)
4. Run test — it should PASS
5. Refactor (IMPROVE)
6. Target 80%+ coverage

### Code Style
- Many small files > few large files (200-400 lines typical, 800 max)
- Group imports: `std` → external crates → `crate`/`super`, separated by blank lines
- Types: PascalCase, functions/variables: snake_case, constants: UPPER_SNAKE_CASE
- Always handle errors explicitly — never silently swallow
- Immutable data preferred — create new objects, don't mutate

### Git Workflow
- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`
- Feature branches from `main`, PRs required
- CI: `cargo fmt --check`, `cargo clippy`, `cargo test`, `cargo xtask build-ebpf`

## File Structure

```
agent-watchdog-common/   # Shared types (kernel + user space), #[repr(C)], no_std
agent-watchdog-ebpf/     # eBPF kernel-space program (no_std, bpfel-unknown-none target)
agent-watchdog/           # User-space daemon (tokio, aya, clap)
xtask/                   # Build helper for cross-compiling eBPF
```

## Build & Run

```bash
cargo xtask build-ebpf                    # Build eBPF program (release)
cargo build --release --target x86_64-unknown-linux-gnu  # Cross-compile daemon
RUST_LOG=info sudo -E ./agent-watchdog    # Run on Linux with root
```

## Key Patterns

### Adding a New Sensitive Keyword
1. Add keyword to `SENSITIVE_KEYWORDS` in `agent-watchdog/src/main.rs`
2. Keyword must be lowercase (comparison is case-insensitive)
3. Test with `cat /path/to/matching/file` on Linux

### Adding New Event Fields
1. Update `FileOpenEvent` in `agent-watchdog-common/src/lib.rs` (must be `#[repr(C)]`, fixed-size)
2. Populate the field in `agent-watchdog-ebpf/src/main.rs` (respect 512-byte stack limit)
3. Read the field in `agent-watchdog/src/main.rs` event processing loop
