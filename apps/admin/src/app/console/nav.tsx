'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { Building2, KeyRound, LayoutDashboard, LogOut, Monitor, Rocket, ScrollText, ShieldAlert, SlidersHorizontal, Users } from 'lucide-react';
import { can, type Permission, type Role } from '@/lib/rbac';
import { Logo } from '@/components/ui';
import { useConsole } from './provider';

const GROUPS: { title: string; items: { href: string; label: string; icon: typeof Monitor; perm: Permission }[] }[] = [
  {
    title: 'Operations',
    items: [
      { href: '/console', label: 'Overview', icon: LayoutDashboard, perm: 'telemetry:read' },
      { href: '/console/devices', label: 'Devices', icon: Monitor, perm: 'device:read' },
      { href: '/console/events', label: 'Security events', icon: ShieldAlert, perm: 'telemetry:read' },
    ],
  },
  {
    title: 'Management',
    items: [
      { href: '/console/organizations', label: 'Organizations', icon: Building2, perm: 'org:read' },
      { href: '/console/licenses', label: 'Licenses', icon: KeyRound, perm: 'license:read' },
      { href: '/console/policies', label: 'Policies', icon: SlidersHorizontal, perm: 'policy:read' },
    ],
  },
  { title: 'Distribution', items: [{ href: '/console/releases', label: 'Releases', icon: Rocket, perm: 'release:read' }] },
  {
    title: 'Administration',
    items: [
      { href: '/console/users', label: 'Users and roles', icon: Users, perm: 'user:manage_roles' },
      { href: '/console/audit', label: 'Audit log', icon: ScrollText, perm: 'audit:read' },
    ],
  },
];

const ROLE_LABEL: Record<Role, string> = { super_admin: 'Super Administrator', security_admin: 'Security Administrator', org_admin: 'Organization Administrator', support: 'Support Operator', auditor: 'Read-only Auditor' };

export function Nav({ role, email }: { role: Role; email: string }) {
  const path = usePathname();
  const router = useRouter();
  const { call } = useConsole();
  return (
    <nav aria-label="Console" className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r border-line bg-elev">
      <div className="flex h-14 items-center gap-2.5 px-4">
        <Logo size={26} />
        <span className="text-[13px] font-semibold tracking-[0.12em] text-ink">SENTRIX</span>
        <span className="rounded bg-surface2 px-1.5 py-0.5 text-[11px] font-semibold text-muted">Console</span>
      </div>
      <div className="flex-1 space-y-4 overflow-auto px-2 pb-3">
        {GROUPS.map((g) => {
          const items = g.items.filter((i) => can(role, i.perm));
          if (!items.length) return null;
          return (
            <div key={g.title}>
              <div className="px-3 pb-1 text-xs font-semibold text-faint">{g.title}</div>
              <ul>
                {items.map(({ href, label, icon: Icon }) => {
                  const active = href === '/console' ? path === href : path.startsWith(href);
                  return (
                    <li key={href}>
                      <Link href={href} aria-current={active ? 'page' : undefined} className={`relative flex h-8 items-center gap-2.5 rounded px-3 text-sm transition-colors ${active ? 'bg-surface2 font-semibold text-ink' : 'text-muted hover:bg-surface2/70 hover:text-ink'}`}>
                        {active && <span className="absolute inset-y-1.5 left-0 w-[3px] rounded-full bg-accent" aria-hidden />}
                        <Icon className="size-4" strokeWidth={1.6} aria-hidden />
                        {label}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </div>
      <div className="border-t border-line px-4 py-3 text-xs">
        <div className="truncate font-semibold text-ink" title={email}>{email}</div>
        <div className="mt-0.5 text-muted">{ROLE_LABEL[role]}</div>
        <button
          className="mt-2 flex items-center gap-1.5 text-muted hover:text-ink"
          onClick={async () => {
            await call('/api/auth/logout', { method: 'POST' }).catch(() => undefined);
            router.replace('/login');
            router.refresh();
          }}
        >
          <LogOut className="size-3.5" /> Sign out
        </button>
      </div>
    </nav>
  );
}
