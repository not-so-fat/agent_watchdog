#![no_std]

// ── Shared constants ─────────────────────────────────────────────

/// Name of the BPF `HashMap` used to store "watched PIDs".
///
/// Only PIDs present in this map are monitored by the eBPF probe.
/// Both the kernel-side eBPF program and the user-space daemon
/// reference this constant to ensure they agree on the map name.
pub const WATCHED_PIDS_MAP_NAME: &str = "WATCHED_PIDS";

/// Maximum number of PIDs that can be simultaneously watched.
pub const WATCHED_PIDS_MAX_ENTRIES: u32 = 1024;

// ── Re-export for non-no_std dependents (user-space) ─────────────
// The types below (`CommandEnvelope`, `RiskLevel`) require `alloc`
// (they use `String`).  They live behind #[cfg(feature = "user")]
// so the eBPF build (no_std, no alloc) is unaffected.

/// Shared event struct passed from kernel-space eBPF to user-space.
///
/// # Layout
///
/// MUST be `#[repr(C)]` to guarantee a stable, deterministic memory layout
/// that both the eBPF verifier (kernel side) and the user-space deserializer
/// agree on.  Never use Rust enums, `Option`, `String`, `Vec`, or any
/// heap-allocated / dynamically-sized type here.
///
/// | Field      | Type       | Size   | Description                          |
/// |------------|------------|--------|--------------------------------------|
/// | `pid`      | `u32`      | 4 B    | Thread group ID (≈ userspace PID)    |
/// | `comm`     | `[u8; 16]` | 16 B   | Process command name (NUL-padded)    |
/// | `filename` | `[u8; 256]`| 256 B  | Opened file path  (NUL-terminated)   |
///
/// Total: 276 bytes (no padding holes thanks to natural alignment).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    /// Process ID — actually the TGID from `bpf_get_current_pid_tgid() >> 32`.
    pub pid: u32,
    /// Process command name, up to 16 bytes including NUL terminator,
    /// obtained via `bpf_get_current_comm()`.
    pub comm: [u8; 16],
    /// File path being opened, up to 256 bytes including NUL terminator,
    /// read from user-space via `bpf_probe_read_user_str()`.
    pub filename: [u8; 256],
}

/// Implement `aya::Pod` in user-space builds so that `PerfEventArray` can
/// safely reinterpret raw bytes as `FileOpenEvent`.
///
/// # Safety
///
/// `FileOpenEvent` is `#[repr(C)]`, `Copy`, contains only fixed-size
/// integer/byte-array fields, and has no padding holes — it is safe to
/// transmute from an arbitrary byte slice of the correct length.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileOpenEvent {}

// ── Anti-Hijack Types (user-space only) ──────────────────────────
//
// These types require heap allocation (`String`, `serde_json::Value`)
// and are therefore only available in user-space builds.

#[cfg(feature = "user")]
extern crate alloc;

/// Signed command envelope for anti-hijack protection.
///
/// Every mutating request MUST be wrapped in a `CommandEnvelope` so
/// the gateway can verify authenticity, prevent replay attacks, and
/// enforce step-up authentication for high-risk operations.
#[cfg(feature = "user")]
#[derive(Debug, Clone)]
pub struct CommandEnvelope {
    /// The authenticated user who issued this command.
    pub user_id: alloc::string::String,
    /// Unique device / client identifier (fingerprint).
    pub device_id: alloc::string::String,
    /// Unix timestamp (seconds) when the command was created.
    pub timestamp: i64,
    /// One-time nonce to prevent replay attacks.
    pub nonce: alloc::string::String,
    /// HMAC-SHA256 (or similar) signature over the canonical payload.
    pub signature: alloc::string::String,
    /// The JSON payload describing the actual tool-call request.
    pub payload: alloc::string::String,
}

/// Threat-level classification for incoming commands.
///
/// Used by the risk-based policy gate to decide whether step-up
/// authentication is required before execution.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    /// Low-risk: read-only or informational operations.
    Low,
    /// Medium-risk: mutating but non-destructive operations.
    Medium,
    /// High-risk: destructive, privileged, or exfiltration-capable
    /// operations.  Requires step-up authentication.
    High,
}
