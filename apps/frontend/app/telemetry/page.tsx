import type { Metadata } from "next";

import { ModulePage } from "@/src/components/module-page";

export const metadata: Metadata = { title: "Telemetria" };

export default function TelemetryPage() {
  return (
    <ModulePage
      capability="Observabilidade sem falsa disponibilidade"
      dependency="backend"
      description="Acompanhe saúde e sinais operacionais preservando correlação, cardinalidade controlada e redaction."
      eyebrow="Observabilidade"
      icon="telemetry"
      title="Telemetria"
    />
  );
}
