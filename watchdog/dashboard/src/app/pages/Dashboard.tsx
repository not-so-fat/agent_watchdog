import { useState, useEffect, useCallback } from "react";
import { AlertTriangle, Ban, Eye, Activity, Clock, Shield } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { AlertEvent, SystemStats } from "../types";
import { toast } from "sonner";
import {
  fetchStats,
  fetchAlerts,
  blockEvent,
  ignoreEvent,
  connectWebSocket,
} from "../api";

export function Dashboard() {
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [stats, setStats] = useState<SystemStats>({
    todayAlerts: 0,
    activeAlerts: 0,
    blockedProcesses: 0,
    ignoredAlerts: 0,
    totalAlerts: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // ── Fetch data from backend ────────────────────────────────
  const refreshData = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([fetchStats(), fetchAlerts()]);
      setStats(s);
      setAlerts(a);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 5000);
    return () => clearInterval(interval);
  }, [refreshData]);

  // ── WebSocket for real-time events ─────────────────────────
  useEffect(() => {
    const cleanup = connectWebSocket((newEvent) => {
      setAlerts((prev) => [newEvent, ...prev.filter((e) => e.id !== newEvent.id)]);
      fetchStats().then(setStats).catch(console.error);
      toast.warning("New alert detected!", {
        description: `${newEvent.processName} (PID: ${newEvent.pid}) → ${newEvent.filePath}`,
      });
    });
    return cleanup;
  }, []);

  // ── Actions ────────────────────────────────────────────────
  const handleAction = async (id: string, action: "block" | "ignore") => {
    try {
      const res = action === "block" ? await blockEvent(id) : await ignoreEvent(id);
      if (res.success) {
        setAlerts((prev) =>
          prev.map((alert) =>
            alert.id === id
              ? {
                ...alert,
                status: action === "block" ? ("blocked" as const) : ("ignored" as const),
                actionTimestamp: new Date().toISOString(),
              }
              : alert
          )
        );
        fetchStats().then(setStats).catch(console.error);

        if (action === "block") {
          toast.success("Process terminated", {
            description: `PID ${alerts.find((a) => a.id === id)?.pid} has been killed.`,
          });
        } else {
          toast.info("Alert marked as false positive.");
        }
      }
    } catch (err) {
      toast.error("Operation failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return "just now";
    if (diffMins < 60) return `${diffMins} min ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)} hour(s) ago`;
    return date.toLocaleString("en-US");
  };

  return (
    <div className="space-y-6">
      {/* Connection error banner */}
      {error && (
        <div className="p-3 bg-background border border-destructive text-destructive text-sm">
          ⚠️ {error} — verify backend Agent-WatchDog is running
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>TODAY ALERTS</CardDescription>
            <CardTitle className="text-3xl">{stats.todayAlerts}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Clock className="w-4 h-4" />
              <span>Last 24 hours</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>ACTIVE ALERTS</CardDescription>
            <CardTitle className="text-3xl text-destructive">
              {stats.activeAlerts}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Activity className="w-4 h-4" />
              <span>Requires action</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>BLOCKED PROCESSES</CardDescription>
            <CardTitle className="text-3xl">{stats.blockedProcesses}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Ban className="w-4 h-4" />
              <span>All time</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>FALSE POSITIVES</CardDescription>
            <CardTitle className="text-3xl">{stats.ignoredAlerts}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Eye className="w-4 h-4" />
              <span>Ignored</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Alerts */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>REAL-TIME ALERTS</CardTitle>
              <CardDescription>
                High-risk file access requiring immediate review.
              </CardDescription>
            </div>
            <Badge variant="destructive" className="h-6">
              {alerts.length} active alert(s)
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>No active alerts.</p>
              <p className="text-sm mt-1">
                System status: stable — all processes under watch.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className="border border-destructive bg-background p-4"
                >
                  <div className="flex items-start gap-4">
                    <div className="w-10 h-10 border border-destructive flex items-center justify-center flex-shrink-0">
                      <AlertTriangle className="w-5 h-5 text-destructive" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2">
                        <h3 className="font-semibold">High-risk file access</h3>
                        <Badge variant="destructive">{alert.severity}</Badge>
                        <span className="text-sm text-muted-foreground ml-auto">
                          {formatTimestamp(alert.timestamp)}
                        </span>
                      </div>
                      <div className="space-y-1 text-sm">
                        <p className="text-foreground">
                          Process{" "}
                          <code className="px-2 py-0.5 bg-background border border-border">
                            {alert.processName}
                          </code>{" "}
                          (PID:{" "}
                          <code className="px-2 py-0.5 bg-background border border-border">
                            {alert.pid}
                          </code>
                          ) attempted to read a sensitive file
                        </p>
                        <p className="text-muted-foreground">
                          File path:{" "}
                          <code className="px-2 py-0.5 bg-background border border-border font-mono text-xs">
                            {alert.filePath}
                          </code>
                        </p>
                      </div>
                      <div className="flex gap-2 mt-4">
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => handleAction(alert.id, "block")}
                        >
                          <Ban className="w-4 h-4 mr-2" />
                          BLOCK PROCESS
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleAction(alert.id, "ignore")}
                        >
                          <Eye className="w-4 h-4 mr-2" />
                          MARK FALSE POSITIVE
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
