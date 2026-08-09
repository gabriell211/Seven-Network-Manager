export type StatusTone = "neutral" | "success" | "warning" | "danger";

export function statusLabel(tone: StatusTone): string {
  const labels: Record<StatusTone, string> = {
    neutral: "Neutro",
    success: "Saudavel",
    warning: "Atencao",
    danger: "Critico",
  };

  return labels[tone];
}
