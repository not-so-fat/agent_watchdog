/**
 * Watchdog-Lite: PID-aware command-blocking for macOS.
 *
 * Provides PID registration, process-tree tracking (via `ps`),
 * and an in-memory + SQLite event store for blocked-command events.
 * Designed to run inside Pulse on macOS where the full Rust/eBPF
 * Watchdog is unavailable.
 */

import { execSync } from "child_process";
import crypto from "crypto";
import { db } from "./db";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PidSetName = "cursor" | "pulse";

export interface PidSetEntry {
  name: PidSetName;
  rootPid: number;
  registeredAt: number;
}

export interface ProcessNode {
  pid: number;
  ppid: number;
  comm: string;
}

export type WatchdogEventType =
  | "command_blocked"
  | "command_allowed"
  | "file_observed"
  | "process_spawned"
  | "pid_registered";

export interface WatchdogEvent {
  id: string;
  type: WatchdogEventType;
  timestamp: number;
  pid: number;
  ppid: number;
  command: string;
  args: string[];
  source_pid_set: PidSetName | "unknown";
  detail: string;
  dismissed: boolean;
}

// ---------------------------------------------------------------------------
// PID Set Management
// ---------------------------------------------------------------------------

const pidSets = new Map<PidSetName, PidSetEntry>();

export function registerPid(name: PidSetName, pid: number): PidSetEntry {
  const entry: PidSetEntry = { name, rootPid: pid, registeredAt: Date.now() };
  pidSets.set(name, entry);
  addEvent({
    type: "pid_registered",
    pid,
    ppid: 0,
    command: name,
    args: [],
    source_pid_set: name,
    detail: `Registered ${name} root PID ${pid}`,
  });
  return entry;
}

export function unregisterPid(name: PidSetName): boolean {
  return pidSets.delete(name);
}

export function getPidSets(): Record<
  string,
  PidSetEntry & { children: ProcessNode[] }
> {
  const result: Record<string, PidSetEntry & { children: ProcessNode[] }> = {};
  for (const [name, entry] of pidSets) {
    result[name] = { ...entry, children: getProcessTree(entry.rootPid) };
  }
  return result;
}

export function getPidSet(name: PidSetName): PidSetEntry | undefined {
  return pidSets.get(name);
}

// ---------------------------------------------------------------------------
// Process Tree (macOS / Linux compatible via `ps`)
// ---------------------------------------------------------------------------

export function getProcessTree(rootPid: number): ProcessNode[] {
  try {
    const raw = execSync(
      `ps -eo pid,ppid,comm 2>/dev/null || ps -eo pid,ppid,args 2>/dev/null`,
      { encoding: "utf-8", timeout: 3000 }
    );
    const lines = raw.trim().split("\n").slice(1); // skip header
    const all: ProcessNode[] = lines
      .map((l) => {
        const parts = l.trim().split(/\s+/);
        if (!parts || parts.length < 3) return null;
        return {
          pid: parseInt(parts[0]!, 10),
          ppid: parseInt(parts[1]!, 10),
          comm: parts.slice(2).join(" "),
        } as ProcessNode;
      })
      .filter(Boolean) as ProcessNode[];

    // BFS from rootPid
    const children: ProcessNode[] = [];
    const visited = new Set<number>();
    const queue = [rootPid];
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);
      for (const proc of all) {
        if (proc.ppid === current && !visited.has(proc.pid)) {
          children.push(proc);
          queue.push(proc.pid);
        }
      }
    }
    return children;
  } catch {
    return [];
  }
}

/**
 * Walk from `pid` up the process tree and return the chain of ancestor PIDs.
 * Stops at PID 1 (init/launchd) or after 64 hops.
 */
export function getAncestorChain(pid: number): number[] {
  const chain: number[] = [];
  let current = pid;
  for (let i = 0; i < 64; i++) {
    try {
      const ppidStr = execSync(`ps -o ppid= -p ${current}`, {
        encoding: "utf-8",
        timeout: 2000,
      }).trim();
      const ppid = parseInt(ppidStr, 10);
      if (isNaN(ppid) || ppid <= 1) break;
      chain.push(ppid);
      current = ppid;
    } catch {
      break;
    }
  }
  return chain;
}

/**
 * Determine which PID set a given process belongs to by checking
 * whether any of its ancestors is a registered root PID.
 */
export function classifyPid(pid: number): PidSetName | "unknown" {
  const ancestors = getAncestorChain(pid);
  const pidChain = [pid, ...ancestors];
  for (const [name, entry] of pidSets) {
    if (pidChain.includes(entry.rootPid)) return name;
  }
  return "unknown";
}

/**
 * Auto-detect Cursor's root PID by scanning running processes.
 * Looks for processes named "Cursor" or "Cursor Helper" (macOS Electron app).
 */
export function autoDetectCursorPid(): number | null {
  try {
    const raw = execSync(
      `ps -eo pid,comm 2>/dev/null | grep -i "Cursor" | grep -v grep | head -1`,
      { encoding: "utf-8", timeout: 3000 }
    ).trim();
    if (!raw) return null;
    const pid = parseInt(raw.trim().split(/\s+/)[0] ?? "", 10);
    return isNaN(pid) ? null : pid;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Event Store (in-memory ring buffer + SQLite persistence)
// ---------------------------------------------------------------------------

const MAX_EVENTS = 2000;
const events: WatchdogEvent[] = [];

export function addEvent(
  partial: Omit<WatchdogEvent, "id" | "timestamp" | "dismissed">
): WatchdogEvent {
  const event: WatchdogEvent = {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    dismissed: false,
    ...partial,
  };
  events.unshift(event); // newest first
  if (events.length > MAX_EVENTS) events.pop();

  // Persist to SQLite (best-effort)
  try {
    db.prepare(
      `INSERT OR IGNORE INTO Watchdog_Events
       (id, type, timestamp, pid, ppid, command, args, source_pid_set, detail, dismissed)
       VALUES (@id, @type, @timestamp, @pid, @ppid, @command, @args, @source_pid_set, @detail, @dismissed)`
    ).run({
      id: event.id,
      type: event.type,
      timestamp: event.timestamp,
      pid: event.pid,
      ppid: event.ppid,
      command: event.command,
      args: JSON.stringify(event.args),
      source_pid_set: event.source_pid_set,
      detail: event.detail,
      dismissed: event.dismissed ? 1 : 0,
    });
  } catch {
    // in-memory is sufficient for demo
  }
  return event;
}

export function getEvents(opts?: {
  type?: WatchdogEventType;
  source?: PidSetName | "unknown";
  limit?: number;
  since?: number;
}): WatchdogEvent[] {
  let result = events;
  if (opts?.type) result = result.filter((e) => e.type === opts.type);
  if (opts?.source)
    result = result.filter((e) => e.source_pid_set === opts.source);
  if (opts?.since !== undefined) result = result.filter((e) => e.timestamp >= opts.since!);
  if (opts?.limit) result = result.slice(0, opts.limit);
  return result;
}

export function dismissEvent(id: string): boolean {
  const ev = events.find((e) => e.id === id);
  if (!ev) return false;
  ev.dismissed = true;
  try {
    db.prepare(`UPDATE Watchdog_Events SET dismissed = 1 WHERE id = ?`).run(id);
  } catch {
    // best-effort
  }
  return true;
}

export function getStats(): {
  total_events: number;
  commands_blocked: number;
  commands_allowed: number;
  files_observed: number;
  pid_sets_registered: number;
} {
  return {
    total_events: events.length,
    commands_blocked: events.filter((e) => e.type === "command_blocked").length,
    commands_allowed: events.filter((e) => e.type === "command_allowed").length,
    files_observed: events.filter((e) => e.type === "file_observed").length,
    pid_sets_registered: pidSets.size,
  };
}
