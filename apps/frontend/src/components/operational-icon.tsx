import type { SVGProps } from "react";

export type OperationalIconName =
  | "accessPoint"
  | "approve"
  | "archive"
  | "chevronRight"
  | "clock"
  | "edit"
  | "empty"
  | "filter"
  | "firewall"
  | "hostname"
  | "lock"
  | "logout"
  | "monitor"
  | "owner"
  | "plus"
  | "printer"
  | "retire"
  | "router"
  | "search"
  | "serial"
  | "server"
  | "signIn"
  | "switch"
  | "unknown"
  | "user"
  | "vendor";

interface OperationalIconProps extends Omit<SVGProps<SVGSVGElement>, "children"> {
  name: OperationalIconName;
  size?: number;
}

export function OperationalIcon({ name, size = 18, ...props }: OperationalIconProps) {
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

const stroke = { stroke: "currentColor", strokeLinecap: "round" as const, strokeLinejoin: "round" as const, strokeWidth: 1.7 };

const paths: Record<OperationalIconName, React.ReactNode> = {
  accessPoint: <><path d="M12 18v3M8 21h8" {...stroke}/><path d="M7.2 12.8a6.8 6.8 0 0 1 9.6 0M4.4 10a10.7 10.7 0 0 1 15.2 0M10 15.5a2.8 2.8 0 0 1 4 0" {...stroke}/></>,
  approve: <><circle cx="12" cy="12" r="9" {...stroke}/><path d="m8 12 2.6 2.6L16.5 9" {...stroke}/></>,
  archive: <><path d="M4 7h16v13H4zM3 4h18v3H3z" {...stroke}/><path d="M9 11h6" {...stroke}/></>,
  chevronRight: <path d="m9 5 7 7-7 7" {...stroke}/>,
  clock: <><circle cx="12" cy="12" r="9" {...stroke}/><path d="M12 7v5l3 2" {...stroke}/></>,
  edit: <><path d="M4 20h4l11-11-4-4L4 16v4Z" {...stroke}/><path d="m13.5 6.5 4 4" {...stroke}/></>,
  empty: <><rect x="4" y="5" width="16" height="14" rx="2" {...stroke}/><path d="M8 10h8M8 14h5" {...stroke}/></>,
  filter: <path d="M4 5h16l-6 7v5l-4 2v-7L4 5Z" {...stroke}/>,
  firewall: <><path d="M4 5h16v14H4zM4 10h16M4 15h16M9 5v5M15 10v5M10 15v4" {...stroke}/></>,
  hostname: <><rect x="3" y="5" width="18" height="12" rx="2" {...stroke}/><path d="M8 21h8M12 17v4M7 9h5" {...stroke}/></>,
  lock: <><rect x="5" y="10" width="14" height="10" rx="2" {...stroke}/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2" {...stroke}/></>,
  logout: <><path d="M10 5H5v14h5M14 8l4 4-4 4M9 12h9" {...stroke}/></>,
  monitor: <><rect x="3" y="4" width="18" height="13" rx="2" {...stroke}/><path d="M8 21h8M12 17v4" {...stroke}/></>,
  owner: <><circle cx="12" cy="8" r="4" {...stroke}/><path d="M5 21a7 7 0 0 1 14 0" {...stroke}/></>,
  plus: <path d="M12 5v14M5 12h14" {...stroke}/>,
  printer: <><path d="M7 9V4h10v5M7 17H5a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-2" {...stroke}/><path d="M7 14h10v6H7z" {...stroke}/></>,
  retire: <><circle cx="12" cy="12" r="9" {...stroke}/><path d="M8 12h8" {...stroke}/></>,
  router: <><rect x="3" y="7" width="18" height="10" rx="2" {...stroke}/><path d="M7 12h.01M11 12h.01M15 12h2M8 7V4M16 7V4" {...stroke}/></>,
  search: <><circle cx="10.5" cy="10.5" r="6.5" {...stroke}/><path d="m15.5 15.5 4 4" {...stroke}/></>,
  serial: <><rect x="4" y="6" width="16" height="12" rx="2" {...stroke}/><path d="M8 10h8M8 14h5" {...stroke}/></>,
  server: <><rect x="4" y="4" width="16" height="6" rx="1.5" {...stroke}/><rect x="4" y="14" width="16" height="6" rx="1.5" {...stroke}/><path d="M8 7h.01M8 17h.01M12 7h5M12 17h5" {...stroke}/></>,
  signIn: <><path d="M14 5h5v14h-5M10 8l4 4-4 4M4 12h10" {...stroke}/></>,
  switch: <><rect x="3" y="7" width="18" height="10" rx="2" {...stroke}/><path d="M7 11h2M11 11h2M15 11h2M7 14h2M11 14h2M15 14h2" {...stroke}/></>,
  unknown: <><circle cx="12" cy="12" r="9" {...stroke}/><path d="M9.8 9a2.4 2.4 0 0 1 4.5 1.2c0 1.8-2.3 2-2.3 3.7M12 17h.01" {...stroke}/></>,
  user: <><circle cx="12" cy="8" r="4" {...stroke}/><path d="M5 21a7 7 0 0 1 14 0" {...stroke}/></>,
  vendor: <><path d="M4 20V9l5 3V8l5 3V5l6 3v12H4Z" {...stroke}/><path d="M8 16h2M14 16h2" {...stroke}/></>,
};
