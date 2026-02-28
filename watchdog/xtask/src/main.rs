//! xtask — build helper for the Agent-WatchDog eBPF program.
//!
//! Usage:
//!
//! ```bash
//! cargo xtask build-ebpf          # release build (default & recommended)
//! cargo xtask build-ebpf --release  # explicit release flag (same result)
//! ```
//!
//! This invokes `cargo +nightly build` inside the `agent-watchdog-ebpf`
//! crate with the `bpfel-unknown-none` target (eBPF little-endian, no OS)
//! and `-Z build-std=core` to cross-compile `core` for that target.

use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Cross-compile the eBPF kernel-space program.
    BuildEbpf {
        /// Build in release mode (default: true).
        /// The eBPF verifier almost always rejects debug builds,
        /// so we default to release.
        #[clap(long, default_value_t = true)]
        release: bool,
    },
}

fn build_ebpf(release: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");

    // Determine the target architecture for eBPF bindings.
    // On macOS (cross-compiling for a Linux eBPF target), the HOST triple
    // is e.g. "aarch64-apple-darwin", and aya-build's build script will
    // automatically extract "aarch64" from it.
    //
    // IMPORTANT: Do NOT set CARGO_CFG_BPF_TARGET_ARCH here.  That env var
    // tells aya-build's `emit_bpf_target_arch_cfg()` that the cfg was
    // already passed to the compiler via RUSTFLAGS, so it skips emitting
    // the `rustc-cfg` directive — but we haven't actually set it in
    // RUSTFLAGS, which causes the "no helpers in generated" error.
    //
    // Instead, pass the cfg flag explicitly via RUSTFLAGS.
    let arch = std::env::consts::ARCH; // e.g. "aarch64" or "x86_64"

    cmd.current_dir("agent-watchdog-ebpf")
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            format!("--cfg=bpf_target_arch=\"{}\"", arch),
        )
        .args([
            "+nightly",
            "build",
            "--target=bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ]);

    if release {
        cmd.arg("--release");
    }

    println!("▶ Building eBPF program…");
    println!("  command: {:?}", cmd);

    let status = cmd
        .status()
        .context("failed to execute cargo for eBPF build — is `cargo` in PATH?")?;

    if !status.success() {
        bail!("eBPF build failed (exit status: {})", status);
    }

    println!("✅  eBPF build succeeded.");
    println!(
        "   Output: agent-watchdog-ebpf/target/bpfel-unknown-none/{}/agent-watchdog",
        if release { "release" } else { "debug" }
    );

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::BuildEbpf { release } => build_ebpf(release),
    }
}
