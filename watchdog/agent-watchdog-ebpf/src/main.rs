#![no_std]
#![no_main]

//! Agent-WatchDog — eBPF kernel-space program
//!
//! Attaches to the `syscalls/sys_enter_openat` tracepoint and captures
//! every `openat(2)` call system-wide.  Each event is pushed to a
//! `PerfEventArray` for the user-space daemon to consume.
//!
//! # Verifier considerations
//!
//! * We NEVER dereference user-space pointers directly.  All reads go
//!   through `bpf_probe_read_user_str`, which is the only helper the
//!   verifier trusts for accessing user memory.
//! * The program must be compiled with `opt-level >= 2` and `panic = "abort"`
//!   or the verifier will reject it.
//! * Large structs (like `FileOpenEvent` at 276 bytes) must NOT live on the
//!   stack — the eBPF stack limit is 512 bytes.  We use a single-element
//!   `PerCpuArray` as a scratch buffer instead.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::TracePointContext,
};
use agent_watchdog_common::FileOpenEvent;

// ── Map definitions ──────────────────────────────────────────────

/// Per-CPU perf ring buffer shared with user-space.
#[map]
static EVENTS: PerfEventArray<FileOpenEvent> = PerfEventArray::new(0);

/// Per-CPU scratch buffer for building `FileOpenEvent`.
///
/// The eBPF stack is limited to 512 bytes.  `FileOpenEvent` alone is
/// 276 bytes, and with the filename temp buffer that would blow the
/// stack.  By placing the struct in a `PerCpuArray` (one element per
/// CPU, index 0), we move it to map memory which has no size limit.
///
/// This is safe because eBPF programs run with preemption disabled
/// on a single CPU — no other program can clobber our entry while
/// we're using it.
#[map]
static SCRATCH: PerCpuArray<FileOpenEvent> = PerCpuArray::with_max_entries(1, 0);

/// PID filter map (`BPF_MAP_TYPE_HASH`).
///
/// Keys are `u32` PIDs, values are `u8` (presence flag — the value
/// is unused, we only check existence).  When this map is non-empty
/// only PIDs present in the map are monitored.
///
/// The user-space daemon populates it on startup (from `target_pids`
/// in the config) and at runtime via `POST /api/config/watch-pid`.
///
/// The map name `WATCHED_PIDS` matches the constant
/// `agent_watchdog_common::WATCHED_PIDS_MAP_NAME`.
#[map]
static WATCHED_PIDS: HashMap<u32, u8> =
    HashMap::<u32, u8>::with_max_entries(1024, 0);

// ── Tracepoint handler ───────────────────────────────────────────

/// Entry point — attached to `syscalls/sys_enter_openat`.
///
/// The tracepoint args struct for `sys_enter_openat` has a
/// common header followed by the syscall arguments.  The actual
/// offsets depend on the kernel — check the format file:
///
/// ```bash
/// sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
/// ```
///
/// Typical layout on x86_64 Linux 5.10:
///
/// ```text
/// common fields:                          offset  0 (8 bytes total)
/// __syscall_nr (int, padded):             offset  8  (8 bytes)
/// dfd          (int, padded to long):     offset 16  (8 bytes)
/// filename     (const char *):            offset 24  ← target
/// flags        (int, padded to long):     offset 32  (8 bytes)
/// mode         (umode_t, padded to long): offset 40  (8 bytes)
/// ```
#[tracepoint]
pub fn agent_watchdog(ctx: TracePointContext) -> u32 {
    match try_agent_watchdog(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // silently drop on error — never panic in eBPF
    }
}

#[inline(always)]
fn try_agent_watchdog(ctx: &TracePointContext) -> Result<u32, i64> {
    // ── 0. PID filter — only monitor watched PIDs ────────────────
    //
    // Get the current TGID (which corresponds to the userspace PID).
    // If the PID is NOT in the WATCHED_PIDS map, skip the event
    // immediately — avoids the overhead of reading the filename and
    // building the event struct for uninteresting processes.
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if unsafe { WATCHED_PIDS.get(&pid) }.is_none() {
        return Ok(0);
    }

    // ── 1. Extract the user-space filename pointer ───────────────
    // Offset 24 = the `filename` field in the tracepoint args.
    // Verify with: sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
    let filename_ptr: *const u8 = unsafe { ctx.read_at::<u64>(24)? as *const u8 };

    // ── 2. Get a mutable reference to the scratch buffer ─────────
    //
    // `get_ptr_mut(0)` returns a raw pointer to the single element
    // in the per-CPU array.  We check for null (required by the
    // verifier) then use it as our working area.
    let event_ptr = SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
    let event = unsafe { &mut *event_ptr };

    // ── 3. Safely copy the filename from user memory ─────────────
    //
    // CRITICAL: `bpf_probe_read_user_str_bytes` is the ONLY safe way
    // to read user-space strings.  Direct pointer dereference will be
    // rejected by the verifier.
    //
    // Zero the filename buffer first so stale data from a previous
    // event on this CPU doesn't leak through.
    event.filename = [0u8; 256];
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) };

    // ── 4. Obtain PID and process name ───────────────────────────
    // Reuse the PID extracted in step 0 (avoid a redundant helper call).
    event.pid = pid;
    event.comm = bpf_get_current_comm().map_err(|e| e as i64)?;

    // ── 5. Push the event to the perf ring ───────────────────────
    EVENTS.output(ctx, event, 0);

    Ok(0)
}

// ── Panic handler ────────────────────────────────────────────────
/// Required by `#![no_std]` + `#![no_main]`.  eBPF programs must
/// never panic — if we somehow reach this, trap into unreachable.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
