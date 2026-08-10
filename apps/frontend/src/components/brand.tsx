import Link from "next/link";

interface BrandProps {
  compact?: boolean;
}

export function Brand({ compact = false }: BrandProps) {
  return (
    <Link aria-label="Seven Network Manager - Dashboard" className="brand" href="/">
      <svg aria-hidden="true" className="brand__mark" fill="none" viewBox="0 0 48 48">
        <path d="M12 8h24l-3.4 7H18.4l-2.3 4.7h13.1c5.2 0 8.8 3.3 8.8 8.2C38 35.1 32 40 23.7 40c-6 0-10.9-2.4-13.7-6.8l6.2-4c1.8 2.6 4.2 4 7.5 4 3.7 0 6.3-1.8 6.3-4.6 0-1.7-1.4-2.7-3.5-2.7H6L12 8Z" fill="currentColor" />
        <path d="M31.7 8H42l-8.5 17.2a11 11 0 0 0-5.9-4.8L31.7 8Z" fill="currentColor" opacity=".45" />
      </svg>
      {!compact ? (
        <span className="brand__text">
          <strong>Seven</strong>
          <span>Network Manager</span>
        </span>
      ) : null}
    </Link>
  );
}
