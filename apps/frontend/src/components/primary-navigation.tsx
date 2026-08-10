"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Icon, type IconName } from "./icon";

const navigation: ReadonlyArray<{ href: string; label: string; icon: IconName }> = [
  { href: "/", label: "Dashboard", icon: "dashboard" },
  { href: "/inventory", label: "Inventário", icon: "inventory" },
  { href: "/ipam", label: "IPAM", icon: "ipam" },
  { href: "/discovery", label: "Discovery", icon: "discovery" },
  { href: "/telemetry", label: "Telemetria", icon: "telemetry" },
];

export function PrimaryNavigation() {
  const pathname = usePathname();

  return (
    <nav aria-label="Navegação principal" className="primary-nav">
      {navigation.map((item) => {
        const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);

        return (
          <Link
            aria-current={active ? "page" : undefined}
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
