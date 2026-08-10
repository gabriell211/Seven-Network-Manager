import type { SVGProps } from "react";

export type IconName =
  | "activity"
  | "database"
  | "dashboard"
  | "discovery"
  | "inventory"
  | "ipam"
  | "network"
  | "offline"
  | "refresh"
  | "redis"
  | "runtime"
  | "settings"
  | "shield"
  | "telemetry"
  | "warning";

interface IconProps extends Omit<SVGProps<SVGSVGElement>, "children"> {
  name: IconName;
  size?: number;
}

export function Icon({ name, size = 20, ...props }: IconProps) {
  return (
    <svg
      aria-hidden="true"
      fill="none"
      focusable="false"
      height={size}
      viewBox="0 0 24 24"
      width={size}
      {...props}
    >
      {paths[name]}
    </svg>
  );
}

const paths: Record<IconName, React.ReactNode> = {
  activity: (
    <path d="M3 12h4l2.2-5 4.1 10 2.2-5H21" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" />
  ),
  database: (
    <>
      <ellipse cx="12" cy="5.5" rx="7.5" ry="3" stroke="currentColor" strokeWidth="1.7" />
      <path d="M4.5 5.5v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6M4.5 11.5v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6" stroke="currentColor" strokeWidth="1.7" />
    </>
  ),
  dashboard: (
    <>
      <rect height="7" rx="1.6" stroke="currentColor" strokeWidth="1.7" width="7" x="3" y="3" />
      <rect height="7" rx="1.6" stroke="currentColor" strokeWidth="1.7" width="7" x="14" y="3" />
      <rect height="7" rx="1.6" stroke="currentColor" strokeWidth="1.7" width="7" x="3" y="14" />
      <rect height="7" rx="1.6" stroke="currentColor" strokeWidth="1.7" width="7" x="14" y="14" />
    </>
  ),
  discovery: (
    <>
      <circle cx="11" cy="11" r="6" stroke="currentColor" strokeWidth="1.7" />
      <path d="m15.5 15.5 4 4M8.5 11h5M11 8.5v5" stroke="currentColor" strokeLinecap="round" strokeWidth="1.7" />
    </>
  ),
  inventory: (
    <>
      <rect height="6" rx="1.5" stroke="currentColor" strokeWidth="1.7" width="16" x="4" y="4" />
      <rect height="6" rx="1.5" stroke="currentColor" strokeWidth="1.7" width="16" x="4" y="14" />
      <path d="M7 7h.01M7 17h.01M11 7h6M11 17h6" stroke="currentColor" strokeLinecap="round" strokeWidth="1.7" />
    </>
  ),
  ipam: (
    <>
      <circle cx="5" cy="12" r="2.2" stroke="currentColor" strokeWidth="1.7" />
      <circle cx="19" cy="6" r="2.2" stroke="currentColor" strokeWidth="1.7" />
      <circle cx="19" cy="18" r="2.2" stroke="currentColor" strokeWidth="1.7" />
      <path d="M7.2 11.2 16.8 6.8M7.2 12.8l9.6 4.4" stroke="currentColor" strokeWidth="1.7" />
    </>
  ),
  network: (
    <>
      <rect height="5" rx="1.3" stroke="currentColor" strokeWidth="1.7" width="8" x="8" y="3" />
      <rect height="5" rx="1.3" stroke="currentColor" strokeWidth="1.7" width="7" x="3" y="16" />
      <rect height="5" rx="1.3" stroke="currentColor" strokeWidth="1.7" width="7" x="14" y="16" />
      <path d="M12 8v4M6.5 16v-2h11v2" stroke="currentColor" strokeLinecap="round" strokeWidth="1.7" />
    </>
  ),
  offline: (
    <>
      <path d="M5 8.8A9 9 0 0 1 19.4 10M8.2 12.1A5.3 5.3 0 0 1 16 13M11 16.3a1.6 1.6 0 0 1 2 .1" stroke="currentColor" strokeLinecap="round" strokeWidth="1.7" />
      <path d="m4 4 16 16" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
    </>
  ),
  refresh: <path d="M20 7v5h-5M4 17v-5h5M18.2 9A7 7 0 0 0 6.1 6.6L4 9M5.8 15A7 7 0 0 0 17.9 17.4L20 15" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />,
  redis: (
    <>
      <path d="m12 4 8 4-8 4-8-4 8-4Z" stroke="currentColor" strokeLinejoin="round" strokeWidth="1.7" />
      <path d="m4 12 8 4 8-4M4 16l8 4 8-4" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />
    </>
  ),
  runtime: (
    <>
      <rect height="14" rx="2" stroke="currentColor" strokeWidth="1.7" width="16" x="4" y="5" />
      <path d="m8 10 2.5 2L8 14M13 14h3" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.7" />
      <path d="M19 13.5v-3l-2-.5a6 6 0 0 0-.6-1.4l1-1.8-2.2-2.2-1.8 1A6 6 0 0 0 12 5l-.5-2h-3L8 5a6 6 0 0 0-1.4.6l-1.8-1-2.2 2.2 1 1.8A6 6 0 0 0 3 10l-2 .5v3l2 .5a6 6 0 0 0 .6 1.4l-1 1.8 2.2 2.2 1.8-1A6 6 0 0 0 8 19l.5 2h3l.5-2a6 6 0 0 0 1.4-.6l1.8 1 2.2-2.2-1-1.8A6 6 0 0 0 17 14l2-.5Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.4" />
    </>
  ),
  shield: <path d="M12 3 19 6v5c0 4.7-2.9 8-7 10-4.1-2-7-5.3-7-10V6l7-3Zm-3 9 2 2 4-4" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />,
  telemetry: (
    <>
      <path d="M4 18V8M9 18V4M14 18v-6M19 18V6" stroke="currentColor" strokeLinecap="round" strokeWidth="1.7" />
      <path d="M3 18h18" stroke="currentColor" strokeLinecap="round" strokeWidth="1.7" />
    </>
  ),
  warning: <path d="M12 4 21 20H3L12 4Zm0 5v5m0 3h.01" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />,
};
