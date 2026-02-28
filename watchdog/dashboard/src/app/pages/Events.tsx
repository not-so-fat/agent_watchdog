import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Input } from "../components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Search } from "lucide-react";
import { AlertEvent } from "../types";
import { fetchEvents } from "../api";

export function Events() {
  const [allEvents, setAllEvents] = useState<AlertEvent[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const loadEvents = useCallback(async () => {
    try {
      const events = await fetchEvents();
      setAllEvents(events);
    } catch (err) {
      console.error("Failed to fetch events:", err);
    }
  }, []);

  useEffect(() => {
    loadEvents();
    const interval = setInterval(loadEvents, 5000);
    return () => clearInterval(interval);
  }, [loadEvents]);

  const filteredAlerts = allEvents.filter((alert) => {
    const matchesSearch =
      alert.processName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.filePath.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.pid.toString().includes(searchQuery);

    const matchesStatus = statusFilter === "all" || alert.status === statusFilter;
    const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  const getStatusBadge = (status: AlertEvent["status"]) => {
    switch (status) {
      case "active":
        return <Badge variant="destructive">ACTIVE</Badge>;
      case "blocked":
        return <Badge className="bg-destructive text-destructive-foreground">
          BLOCKED
        </Badge>;
      case "ignored":
        return <Badge variant="secondary">IGNORED</Badge>;
    }
  };

  const getSeverityBadge = (severity: AlertEvent["severity"]) => {
    switch (severity) {
      case "high":
        return <Badge variant="destructive">HIGH</Badge>;
      case "medium":
        return <Badge className="bg-primary/20 text-primary">MEDIUM</Badge>;
      case "low":
        return <Badge variant="outline">LOW</Badge>;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString("en-US", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold mb-2">Event log</h1>
        <p className="text-muted-foreground">
          Review all security alerts with filters and search.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>FILTERS</CardTitle>
          <CardDescription>
            Use search and filters to locate specific events.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search by process, file path or PID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-full sm:w-[180px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All states</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="blocked">Blocked</SelectItem>
                <SelectItem value="ignored">Ignored</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-full sm:w-[180px]">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All levels</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>EVENTS</CardTitle>
              <CardDescription>
                {filteredAlerts.length} record(s) match the current filter.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Process</TableHead>
                  <TableHead>PID</TableHead>
                  <TableHead>File path</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Action time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAlerts.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={7}
                      className="text-center py-8 text-muted-foreground"
                    >
                      No events match the current filter.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredAlerts.map((alert) => (
                    <TableRow key={alert.id}>
                      <TableCell className="font-mono text-sm">
                        {formatTimestamp(alert.timestamp)}
                      </TableCell>
                      <TableCell>
                        <code className="px-2 py-1 bg-background border border-border text-sm">
                          {alert.processName}
                        </code>
                      </TableCell>
                      <TableCell>
                        <code className="text-sm">{alert.pid}</code>
                      </TableCell>
                      <TableCell className="max-w-xs truncate font-mono text-xs">
                        {alert.filePath}
                      </TableCell>
                      <TableCell>{getSeverityBadge(alert.severity)}</TableCell>
                      <TableCell>{getStatusBadge(alert.status)}</TableCell>
                      <TableCell className="font-mono text-sm text-muted-foreground">
                        {alert.actionTimestamp
                          ? formatTimestamp(alert.actionTimestamp)
                          : "-"}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
