import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Switch } from "../components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "../components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { mockPatterns } from "../data/mockData";
import { SensitivePattern } from "../types";
import { Save, Plus, Trash2, Eye, EyeOff } from "lucide-react";
import { toast } from "sonner";

export function Configuration() {
  const [slackWebhook, setSlackWebhook] = useState("https://hooks.slack.com/services/YOUR/WEBHOOK/URL");
  const [showWebhook, setShowWebhook] = useState(false);
  const [patterns, setPatterns] = useState<SensitivePattern[]>(mockPatterns);
  const [newPattern, setNewPattern] = useState({
    pattern: "",
    description: "",
    severity: "high" as "high" | "medium" | "low",
  });
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  const handleSaveWebhook = () => {
    toast.success("Slack webhook saved.");
  };

  const togglePattern = (id: string) => {
    setPatterns((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p))
    );
  };

  const deletePattern = (id: string) => {
    setPatterns((prev) => prev.filter((p) => p.id !== id));
    toast.success("Rule deleted.");
  };

  const addPattern = () => {
    if (!newPattern.pattern || !newPattern.description) {
      toast.error("Please fill in all fields.");
      return;
    }

    const pattern: SensitivePattern = {
      id: Date.now().toString(),
      pattern: newPattern.pattern,
      description: newPattern.description,
      severity: newPattern.severity,
      enabled: true,
    };

    setPatterns((prev) => [...prev, pattern]);
    setNewPattern({ pattern: "", description: "", severity: "high" });
    setIsDialogOpen(false);
    toast.success("Watch rule added.");
  };

  const getSeverityBadge = (severity: SensitivePattern["severity"]) => {
    switch (severity) {
      case "high":
        return <Badge variant="destructive">HIGH</Badge>;
      case "medium":
        return <Badge className="bg-primary/20 text-primary">MEDIUM</Badge>;
      case "low":
        return <Badge variant="outline">LOW</Badge>;
    }
  };

  const enabledCount = patterns.filter((p) => p.enabled).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold mb-2">Configuration</h1>
        <p className="text-muted-foreground">
          Manage Slack alerting and sensitive file watch rules.
        </p>
      </div>

      {/* Slack Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>SLACK ALERTING</CardTitle>
          <CardDescription>
            Define Slack webhook URL for real-time alert notifications.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="webhook">Webhook URL</Label>
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <Input
                  id="webhook"
                  type={showWebhook ? "text" : "password"}
                  value={slackWebhook}
                  onChange={(e) => setSlackWebhook(e.target.value)}
                  placeholder="https://hooks.slack.com/services/..."
                />
                <button
                  type="button"
                  onClick={() => setShowWebhook(!showWebhook)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showWebhook ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
              <Button onClick={handleSaveWebhook}>
                <Save className="w-4 h-4 mr-2" />
                SAVE
              </Button>
            </div>
            <p className="text-sm text-muted-foreground">
              Need to create a Slack incoming webhook?
              <a
                href="https://api.slack.com/messaging/webhooks"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline ml-1"
              >
                VIEW DOCUMENTATION
              </a>
            </p>
          </div>

          <div className="border-t pt-4">
            <h3 className="font-medium mb-2">Alert payload format</h3>
            <div className="bg-background border border-border p-4 text-sm font-mono space-y-2">
              <div className="text-destructive">
                🚨 Security alert: high-risk file access detected
              </div>
              <div className="text-foreground">PROCESS: cat (PID: 5543)</div>
              <div className="text-foreground">FILE: /home/user/.env</div>
              <div className="text-foreground">TIME: 2026-02-20 10:30:25</div>
              <div className="flex gap-2 mt-3">
                <span className="px-3 py-1 bg-destructive text-destructive-foreground">
                  BLOCK PROCESS
                </span>
                <span className="px-3 py-1 bg-secondary text-foreground">
                  MARK FALSE POSITIVE
                </span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Sensitive Patterns */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>SENSITIVE FILE RULES</CardTitle>
              <CardDescription>
                Define path keywords and match rules ({enabledCount}/{patterns.length} enabled).
              </CardDescription>
            </div>
            <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="w-4 h-4 mr-2" />
                  Add rule
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add watch rule</DialogTitle>
                  <DialogDescription>
                    Define a new sensitive file match rule.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 pt-4">
                  <div className="space-y-2">
                    <Label htmlFor="pattern">Match keyword</Label>
                    <Input
                      id="pattern"
                      placeholder="E.G. .env, id_rsa, secret"
                      value={newPattern.pattern}
                      onChange={(e) =>
                        setNewPattern({ ...newPattern, pattern: e.target.value })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">Rule description</Label>
                    <Input
                      id="description"
                      placeholder="e.g. environment config file"
                      value={newPattern.description}
                      onChange={(e) =>
                        setNewPattern({ ...newPattern, description: e.target.value })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="severity">Severity</Label>
                    <Select
                      value={newPattern.severity}
                      onValueChange={(value: "high" | "medium" | "low") =>
                        setNewPattern({ ...newPattern, severity: value })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button onClick={addPattern} className="w-full">
                    Add rule
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          <div className="border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Keyword</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {patterns.map((pattern) => (
                  <TableRow key={pattern.id}>
                    <TableCell>
                      <code className="px-2 py-1 bg-background border border-border text-sm font-mono">
                        {pattern.pattern}
                      </code>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {pattern.description}
                    </TableCell>
                    <TableCell>{getSeverityBadge(pattern.severity)}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={pattern.enabled}
                          onCheckedChange={() => togglePattern(pattern.id)}
                        />
                        <span className="text-sm text-muted-foreground">
                          {pattern.enabled ? "Enabled" : "Disabled"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => deletePattern(pattern.id)}
                      >
                        <Trash2 className="w-4 h-4 text-red-600" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Additional Settings */}
      <Card>
        <CardHeader>
          <CardTitle>ADVANCED SETTINGS</CardTitle>
          <CardDescription>
            Control system behavior and monitoring strategy.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-4 border border-border">
            <div>
              <h3 className="font-medium">Auto-block mode</h3>
              <p className="text-sm text-muted-foreground">
                Automatically terminate processes on high-risk behavior without manual confirmation.
              </p>
            </div>
            <Switch />
          </div>
          <div className="flex items-center justify_between p-4 border border-border">
            <div>
              <h3 className="font-medium">Detailed logging</h3>
              <p className="text-sm text-muted-foreground">
                Log all file accesses, including non-sensitive paths.
              </p>
            </div>
            <Switch />
          </div>
          <div className="flex items-center justify-between p-4 border border-border">
            <div>
              <h3 className="font-medium">Slack notifications</h3>
              <p className="text-sm text-muted-foreground">
                Send Slack messages when alerts are triggered.
              </p>
            </div>
            <Switch defaultChecked />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
