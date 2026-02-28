import { AlertEvent, ProcessInfo, SensitivePattern, SystemStats } from "../types";

export const mockAlerts: AlertEvent[] = [
  {
    id: "1",
    timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
    pid: 5543,
    processName: "cat",
    filePath: "/home/user/.env",
    severity: "high",
    status: "active",
  },
  {
    id: "2",
    timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
    pid: 7821,
    processName: "python3",
    filePath: "/home/user/.ssh/id_rsa",
    severity: "high",
    status: "blocked",
    actionTimestamp: new Date(Date.now() - 14 * 60000).toISOString(),
  },
  {
    id: "3",
    timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
    pid: 4521,
    processName: "node",
    filePath: "/etc/shadow",
    severity: "high",
    status: "blocked",
    actionTimestamp: new Date(Date.now() - 28 * 60000).toISOString(),
  },
  {
    id: "4",
    timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
    pid: 3214,
    processName: "bash",
    filePath: "/home/user/.aws/credentials",
    severity: "high",
    status: "ignored",
    actionTimestamp: new Date(Date.now() - 40 * 60000).toISOString(),
  },
  {
    id: "5",
    timestamp: new Date(Date.now() - 2 * 3600000).toISOString(),
    pid: 9876,
    processName: "vim",
    filePath: "/home/user/.config/keys.json",
    severity: "medium",
    status: "ignored",
    actionTimestamp: new Date(Date.now() - 2 * 3600000 + 120000).toISOString(),
  },
];

export const mockProcesses: ProcessInfo[] = [
  {
    pid: 5543,
    name: "cat",
    user: "ubuntu",
    startTime: new Date(Date.now() - 5 * 60000).toISOString(),
    isMonitored: true,
    riskScore: 85,
  },
  {
    pid: 1234,
    name: "agent-worker",
    user: "ubuntu",
    startTime: new Date(Date.now() - 3600000).toISOString(),
    isMonitored: true,
    riskScore: 45,
  },
  {
    pid: 8765,
    name: "python3",
    user: "ubuntu",
    startTime: new Date(Date.now() - 7200000).toISOString(),
    isMonitored: true,
    riskScore: 30,
  },
  {
    pid: 2341,
    name: "nodejs",
    user: "root",
    startTime: new Date(Date.now() - 10800000).toISOString(),
    isMonitored: true,
    riskScore: 20,
  },
];

export const mockPatterns: SensitivePattern[] = [
  {
    id: "1",
    pattern: ".env",
    description: "Environment variable config file",
    severity: "high",
    enabled: true,
  },
  {
    id: "2",
    pattern: "id_rsa",
    description: "SSH private key file",
    severity: "high",
    enabled: true,
  },
  {
    id: "3",
    pattern: "shadow",
    description: "System password file",
    severity: "high",
    enabled: true,
  },
  {
    id: "4",
    pattern: "credentials",
    description: "Credential file",
    severity: "high",
    enabled: true,
  },
  {
    id: "5",
    pattern: ".pem",
    description: "Certificate private key file",
    severity: "high",
    enabled: true,
  },
  {
    id: "6",
    pattern: "config.json",
    description: "Configuration file",
    severity: "medium",
    enabled: true,
  },
  {
    id: "7",
    pattern: "secret",
    description: "Secret-related file",
    severity: "high",
    enabled: true,
  },
];

export const mockStats: SystemStats = {
  totalAlerts: 247,
  activeAlerts: 1,
  blockedProcesses: 156,
  ignoredAlerts: 90,
  todayAlerts: 5,
};
