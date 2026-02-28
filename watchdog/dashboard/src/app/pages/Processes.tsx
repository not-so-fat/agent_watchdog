import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Switch } from "../components/ui/switch";
import { Progress } from "../components/ui/progress";
import { mockProcesses } from "../data/mockData";
import { ProcessInfo } from "../types";
import { Activity, User, Clock } from "lucide-react";
import { toast } from "sonner";

export function Processes() {
  const [processes, setProcesses] = useState<ProcessInfo[]>(mockProcesses);

  const toggleMonitoring = (pid: number) => {
    setProcesses((prev) =>
      prev.map((p) =>
        p.pid === pid ? { ...p, isMonitored: !p.isMonitored } : p
      )
    );
    const process = processes.find((p) => p.pid === pid);
    if (process?.isMonitored) {
      toast.info(`Stopped watching process ${process.name} (PID: ${pid}).`);
    } else {
      toast.success(`Started watching process ${process?.name} (PID: ${pid}).`);
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return "text-destructive";
    if (score >= 40) return "text-primary";
    return "text-foreground";
  };

  const getRiskLevel = (score: number) => {
    if (score >= 70) return "High";
    if (score >= 40) return "Medium";
    return "Low";
  };

  const formatUptime = (startTime: string) => {
    const start = new Date(startTime);
    const now = new Date();
    const diffMs = now.getTime() - start.getTime();
    const diffHours = Math.floor(diffMs / 3600000);
    const diffMins = Math.floor((diffMs % 3600000) / 60000);

    if (diffHours > 0) {
      return `${diffHours} H ${diffMins} MIN`;
    }
    return `${diffMins} MIN`;
  };

  const monitoredCount = processes.filter((p) => p.isMonitored).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold mb-2">Process watch</h1>
        <p className="text-muted-foreground">
          Real-time view of system processes and risk scores.
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>TOTAL PROCESSES</CardDescription>
            <CardTitle className="text-3xl">{processes.length}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Activity className="w-4 h-4" />
              <span>Running</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>WATCHED PROCESSES</CardDescription>
            <CardTitle className="text-3xl">{monitoredCount}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Activity className="w-4 h-4" />
              <span>Under active watch</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>HIGH-RISK PROCESSES</CardDescription>
            <CardTitle className="text-3xl text-destructive">
              {processes.filter((p) => p.riskScore >= 70).length}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Activity className="w-4 h-4" />
              <span>Requires review</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Process List */}
      <Card>
        <CardHeader>
          <CardTitle>PROCESS LIST</CardTitle>
          <CardDescription>
            Manage and watch process risk levels.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>PID</TableHead>
                  <TableHead>Process</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Uptime</TableHead>
                  <TableHead>Risk score</TableHead>
                  <TableHead>Risk level</TableHead>
                  <TableHead>Watch status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {processes.map((process) => (
                  <TableRow key={process.pid}>
                    <TableCell>
                      <code className="text-sm font-mono">{process.pid}</code>
                    </TableCell>
                    <TableCell>
                      <code className="px-2 py-1 bg-background border border-border text-sm">
                        {process.name}
                      </code>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <User className="w-4 h-4 text-muted-foreground" />
                        <span className="text-sm">{process.user}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Clock className="w-4 h-4" />
                        {formatUptime(process.startTime)}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-2 min-w-[120px]">
                        <div className="flex items-center justify-between">
                          <span className={`text-sm font-medium ${getRiskColor(process.riskScore)}`}>
                            {process.riskScore}
                          </span>
                          <span className="text-xs text-muted-foreground">/ 100</span>
                        </div>
                        <Progress value={process.riskScore} className="h-2" />
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          process.riskScore >= 70
                            ? "destructive"
                            : process.riskScore >= 40
                            ? "default"
                            : "secondary"
                        }
                      >
                        {getRiskLevel(process.riskScore)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={process.isMonitored}
                          onCheckedChange={() => toggleMonitoring(process.pid)}
                        />
                        <span className="text-sm text-muted-foreground">
                          {process.isMonitored ? "Enabled" : "Disabled"}
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
