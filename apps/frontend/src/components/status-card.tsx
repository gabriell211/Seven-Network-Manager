import { Icon, type IconName } from "./icon";

interface StatusCardProps {
  icon: IconName;
  label: string;
  value: string;
  detail: string;
  status: "ready" | "degraded" | "offline" | "neutral";
}

export function StatusCard({ icon, label, value, detail, status }: StatusCardProps) {
  return (
    <article className="status-card" data-status={status}>
      <div className="status-card__icon"><Icon name={icon} size={21} /></div>
      <div className="status-card__content">
        <span className="status-card__label">{label}</span>
        <strong className="status-card__value">{value}</strong>
        <span className="status-card__detail">{detail}</span>
      </div>
      <span aria-label={`Status: ${status}`} className="status-card__indicator" role="img" />
    </article>
  );
}
