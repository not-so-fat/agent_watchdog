/**
 * API client for Agent-WatchDog backend.
 *
 * The Vite dev server proxies /api/* and /ws/* to the backend
 * (configured in vite.config.ts).
 */

import type { AlertEvent, SystemStats } from "./types";

// ── Type mapping helpers ─────────────────────────────────────────
// Backend uses snake_case, frontend uses camelCase.

interface BackendAlertEvent {
  id: string;
  timestamp: string;
  pid: number;
  comm: string;
  filename: string;
  severity: "high" | "medium" | "low";
  status: "active" | "ignored" | "blocked";
}

interface BackendStats {
  today_alerts: number;
  active_alerts: number;
  blocked_count: number;
  ignored_count: number;
  total_events: number;
}

function mapAlert(raw: BackendAlertEvent): AlertEvent {
  return {
    id: raw.id,
    timestamp: raw.timestamp,
    pid: raw.pid,
    processName: raw.comm,
    filePath: raw.filename,
    severity: raw.severity,
    status: raw.status,
  };
}

function mapStats(raw: BackendStats): SystemStats {
  return {
    todayAlerts: raw.today_alerts,
    activeAlerts: raw.active_alerts,
    blockedProcesses: raw.blocked_count,
    ignoredAlerts: raw.ignored_count,
    totalAlerts: raw.total_events,
  };
}

// ── REST API ─────────────────────────────────────────────────────

export async function fetchStats(): Promise<SystemStats> {
  const res = await fetch("/api/stats");
  if (!res.ok) throw new Error(`GET /api/stats failed: ${res.status}`);
  const raw: BackendStats = await res.json();
  return mapStats(raw);
}

export async function fetchEvents(): Promise<AlertEvent[]> {
  const res = await fetch("/api/events");
  if (!res.ok) throw new Error(`GET /api/events failed: ${res.status}`);
  const raw: BackendAlertEvent[] = await res.json();
  return raw.map(mapAlert);
}

export async function fetchAlerts(): Promise<AlertEvent[]> {
  const res = await fetch("/api/alerts");
  if (!res.ok) throw new Error(`GET /api/alerts failed: ${res.status}`);
  const raw: BackendAlertEvent[] = await res.json();
  return raw.map(mapAlert);
}

export interface ActionResponse {
  success: boolean;
  message: string;
}

export async function blockEvent(id: string): Promise<ActionResponse> {
  const res = await fetch(`/api/events/${id}/block`, { method: "POST" });
  if (!res.ok) throw new Error(`POST block failed: ${res.status}`);
  return res.json();
}

export async function ignoreEvent(id: string): Promise<ActionResponse> {
  const res = await fetch(`/api/events/${id}/ignore`, { method: "POST" });
  if (!res.ok) throw new Error(`POST ignore failed: ${res.status}`);
  return res.json();
}

// ── WebSocket ────────────────────────────────────────────────────

export function connectWebSocket(
  onEvent: (event: AlertEvent) => void,
  onError?: (err: Event) => void
): () => void {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/events`;
  let ws: WebSocket | null = new WebSocket(wsUrl);
  let closed = false;

  ws.onmessage = (msg) => {
    try {
      const raw: BackendAlertEvent = JSON.parse(msg.data);
      onEvent(mapAlert(raw));
    } catch {
      console.warn("Failed to parse WebSocket message:", msg.data);
    }
  };

  ws.onerror = (err) => {
    console.error("WebSocket error:", err);
    onError?.(err);
  };

  ws.onclose = () => {
    if (!closed) {
      console.log("WebSocket closed, reconnecting in 3s...");
      setTimeout(() => {
        if (!closed) connectWebSocket(onEvent, onError);
      }, 3000);
    }
  };

  return () => {
    closed = true;
    ws?.close();
    ws = null;
  };
}
