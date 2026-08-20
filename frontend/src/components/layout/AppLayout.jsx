import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  LayoutDashboard,
  ListTree,
  ShieldAlert,
  FolderOpen,
  ListChecks,
  Globe,
  Users,
  SlidersHorizontal,
  LogOut,
  Shield,
  Menu,
  X,
  FlaskConical,
} from "lucide-react";
import { useAuth } from "@/api/AuthContext";
import { useSetupValidate } from "@/api/hooks";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/events", label: "Events", icon: ListTree },
  { to: "/alerts", label: "Alerts", icon: ShieldAlert },
  { to: "/incidents", label: "Incidents", icon: FolderOpen },
  { to: "/rules", label: "Rules", icon: ListChecks },
  { to: "/ip-intel", label: "IP Intel", icon: Globe },
  { to: "/settings", label: "Settings", icon: SlidersHorizontal },
];

const ADMIN_ITEM = { to: "/admin", label: "Admin", icon: Users };
const ATTACK_LAB_ITEM = { to: "/attack-lab", label: "Attack Lab", icon: FlaskConical };

function SidebarContent({ navItems, user, logout, onNavigate }) {
  return (
    <>
      <div className="flex items-center gap-2 px-5 h-16 border-b border-border shrink-0">
        <Shield className="h-5 w-5 text-primary" />
        <span className="font-semibold tracking-tight">Mini SIEM</span>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              )
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-border p-3 shrink-0">
        <div className="px-2 pb-2 text-xs text-muted-foreground truncate">
          {user?.email} <span className="font-mono">({user?.roles?.join(", ")})</span>
        </div>
        <button
          onClick={logout}
          className="flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
        >
          <LogOut className="h-4 w-4" />
          Log out
        </button>
      </div>
    </>
  );
}

export function AppLayout() {
  const { user, logout } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const isAdmin = user?.roles?.includes("admin");
  // /api/setup/validate is admin-only, so the Attack Lab nav item is only
  // discoverable by admins now. Acceptable: it's a dev-only feature and the
  // routes themselves stay gated by ENABLE_ATTACK_LAB regardless of role.
  const { data: validate } = useSetupValidate(isAdmin);
  let navItems = validate?.attack_lab_enabled ? [...NAV_ITEMS, ATTACK_LAB_ITEM] : NAV_ITEMS;
  if (isAdmin) navItems = [...navItems, ADMIN_ITEM];
  const currentLabel = navItems.find((n) => (n.end ? location.pathname === n.to : location.pathname.startsWith(n.to)))?.label;

  return (
    <div className="min-h-screen flex">
      {/* Desktop sidebar */}
      <aside className="hidden md:flex w-60 shrink-0 border-r border-border bg-card flex-col">
        <SidebarContent navItems={navItems} user={user} logout={logout} />
      </aside>

      {/* Mobile top bar */}
      <div className="md:hidden fixed top-0 inset-x-0 z-40 flex items-center justify-between h-14 px-4 border-b border-border bg-card">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          <span className="font-semibold text-sm">{currentLabel ?? "Mini SIEM"}</span>
        </div>
        <button onClick={() => setMobileOpen(true)} aria-label="Open menu">
          <Menu className="h-5 w-5" />
        </button>
      </div>

      {/* Mobile drawer */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.div
              className="md:hidden fixed inset-0 z-50 bg-black/60"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setMobileOpen(false)}
            />
            <motion.aside
              className="md:hidden fixed inset-y-0 left-0 z-50 w-64 bg-card border-r border-border flex flex-col"
              initial={{ x: "-100%" }}
              animate={{ x: 0 }}
              exit={{ x: "-100%" }}
              transition={{ type: "tween", duration: 0.2 }}
            >
              <button
                onClick={() => setMobileOpen(false)}
                className="absolute top-4 right-3 text-muted-foreground"
                aria-label="Close menu"
              >
                <X className="h-5 w-5" />
              </button>
              <SidebarContent
                navItems={navItems}
                user={user}
                logout={logout}
                onNavigate={() => setMobileOpen(false)}
              />
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      <main className="flex-1 overflow-y-auto p-4 pt-20 md:p-8">
        <Outlet />
      </main>
    </div>
  );
}
