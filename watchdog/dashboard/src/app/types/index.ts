export interface AlertEvent {
  id: string;
  timestamp: string;
  pid: number;
  processName: string;
  filePath: string;
  severity: "high" | "medium" | "low";
  status: "active" | "ignored" | "blocked";
  actionTimestamp?: string;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  user: string;
  startTime: string;
  isMonitored: boolean;
  riskScore: number;
}

export interface SensitivePattern {
  id: string;
  pattern: string;
  description: string;
  severity: "high" | "medium" | "low";
  enabled: boolean;
}

export interface SystemStats {
  totalAlerts: number;
  activeAlerts: number;
  blockedProcesses: number;
  ignoredAlerts: number;
  todayAlerts: number;
}
