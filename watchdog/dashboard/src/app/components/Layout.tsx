import { Link, Outlet, useLocation } from "react-router";
import { Shield, Activity, Settings, List } from "lucide-react";
import { cn } from "./ui/utils";

export function Layout() {
  const location = useLocation();

  const navItems = [
    { path: "/", label: "SYSTEM DASHBOARD", icon: Activity },
    { path: "/events", label: "EVENT LOG", icon: List },
    { path: "/processes", label: "PROCESS WATCH", icon: Shield },
    { path: "/configuration", label: "CONFIGURATION", icon: Settings },
  ];

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="bg-background border-b border-border sticky top-0 z-50">
        <div className="px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 border border-border flex items-center justify-center">
              <Shield className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="font-semibold tracking-wide">AGENT-WATCHDOG</h1>
              <p className="text-xs text-muted-foreground">
                AI agent runtime security monitor
              </p>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className="w-64 bg-background border-r border-border min-h-[calc(100vh-73px)] sticky top-[73px]">
          <nav className="p-4">
            <ul className="space-y-1">
              {navItems.map((item) => {
                const isActive =
                  location.pathname === item.path ||
                  (item.path !== "/" && location.pathname.startsWith(item.path));
                const Icon = item.icon;
                return (
                  <li key={item.path}>
                    <Link
                      to={item.path}
                      className={cn(
                        "flex items-center gap-3 px-4 py-3 transition-colors border border-transparent",
                        isActive
                          ? "bg-secondary text-primary border-border"
                          : "text-muted-foreground hover:bg-secondary"
                      )}
                    >
                      <Icon className="w-5 h-5" />
                      <span>{item.label}</span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
