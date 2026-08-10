"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import type { OperationalContext } from "@/src/generated/api-contract";

import { Icon, type IconName } from "./icon";

interface NavigationItem {
  href: string;
  label: string;
  icon: IconName;
  available: boolean;
}

export function PrimaryNavigation({ context }: { context: OperationalContext | null }) {
  const pathname = usePathname();
  const canViewInventory = context?.sites.some((site) => site.permissions.includes("devices.view")) ?? false;
  const canViewIpam = context?.sites.some((site) => site.permissions.includes("ipam.view")) ?? false;
  const navigation: NavigationItem[] = [
    { href: "/", label: "Dashboard", icon: "dashboard", available: true },
    { href: "/inventory", label: "Inventário", icon: "inventory", available: canViewInventory },
    { href: "/ipam", label: "IPAM", icon: "ipam", available: canViewIpam },
    { href: "/api-docs", label: "Contrato API", icon: "settings", available: true },
  ];

  return (
    <nav aria-label="Navegação principal" className="primary-nav">
      {navigation.filter((item) => item.available).map((item) => {
        const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
        return (
          <Link
            aria-current={active ? "page" : undefined}
            aria-label={item.label}
            className="primary-nav__item"
            data-active={active || undefined}
            href={item.href}
            key={item.href}
          >
            <Icon name={item.icon} size={19} />
            <span>{item.label}</span>
          </Link>
        );
      })}
    </nav>
  );
}
