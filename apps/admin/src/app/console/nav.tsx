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
    <nav aria-label="Console" className="sticky top-0 flex h-screen w-64 shrink-0 flex-col border-r border-line px-3 py-5" style={{ background: 'color-mix(in srgb, var(--bg-elev) 70%, transparent)' }}>
      <div className="mb-6 flex items-center gap-3 px-3">
        <Logo size={34} />
        <div>
          <div className="text-base font-semibold leading-tight text-ink">SENTRIX</div>
          <div className="text-[11px] text-muted">Console</div>
        </div>
      </div>
      <div className="flex-1 space-y-5 overflow-auto">
        {GROUPS.map((g) => {
          const items = g.items.filter((i) => can(role, i.perm));
          if (!items.length) return null;
          return (
            <div key={g.title}>
              <div className="px-3 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">{g.title}</div>
              <ul className="space-y-0.5">
                {items.map(({ href, label, icon: Icon }) => {
                  const active = href === '/console' ? path === href : path.startsWith(href);
                  return (
                    <li key={href}>
                      <Link href={href} aria-current={active ? 'page' : undefined} className={`flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${active ? 'bg-surface2 text-ink' : 'text-muted hover:bg-surface2/60 hover:text-ink'}`}>
                        <Icon className={`size-[18px] ${active ? 'text-accent' : ''}`} strokeWidth={1.8} aria-hidden />
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
      <div className="mt-4 rounded-xl border border-line p-3 text-xs">
        <div className="truncate font-medium text-ink" title={email}>{email}</div>
        <div className="mt-0.5 text-muted">{ROLE_LABEL[role]}</div>
        <button
          className="mt-3 flex items-center gap-2 text-muted hover:text-ink"
          onClick={async () => {
            await call('/api/auth/logout', { method: 'POST' }).catch(() => undefined);
            router.replace('/login');
            router.refresh();
          }}
        >
          <LogOut className="size-4" /> Sign out
        </button>
      </div>
    </nav>
  );
}
