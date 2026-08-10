import Link from "next/link";

import type { IconName } from "./icon";
import { Icon } from "./icon";
import { StatusCard } from "./status-card";
import { getPlatformSnapshot } from "@/src/lib/api";

interface ModulePageProps {
  title: string;
  eyebrow: string;
  description: string;
  icon: IconName;
  dependency: "backend" | "runtime";
  capability: string;
}

export async function ModulePage({ title, eyebrow, description, icon, dependency, capability }: ModulePageProps) {
  const snapshot = await getPlatformSnapshot();
  const systemReady = snapshot.system !== null;
  const runtimeReady = snapshot.readiness?.runtime === "ready";
  const dependencyReady = dependency === "backend" ? systemReady : runtimeReady;

  return (
    <div className="page-stack">
      <section className="page-heading page-heading--module">
        <div className="page-heading__module-icon"><Icon name={icon} size={27} /></div>
        <div className="page-heading__content">
          <span className="eyebrow">{eyebrow}</span>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
        <Link className="button button--secondary" href="/">
          ← Dashboard
        </Link>
      </section>

      <section className="section-block">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Disponibilidade</span>
            <h2>Dependências operacionais</h2>
          </div>
        </div>
        <div className="status-grid status-grid--compact">
          <StatusCard
            detail={snapshot.system?.deploymentMode ?? "Control plane sem resposta"}
            icon="activity"
            label="Control plane"
            status={systemReady ? "ready" : "offline"}
            value={systemReady ? "Operacional" : "Offline"}
          />
          <StatusCard
            detail="Execução LAN isolada"
            icon="runtime"
            label="Site runtime"
            status={runtimeReady ? "ready" : "offline"}
            value={runtimeReady ? "Operacional" : "Indisponível"}
          />
        </div>
      </section>

      <section className="module-state" data-ready={dependencyReady || undefined}>
        <div className="module-state__icon">
          <Icon name={dependencyReady ? "shield" : "warning"} size={24} />
        </div>
        <div>
          <span className="eyebrow">Contrato do módulo</span>
          <h2>{capability}</h2>
          <p>
            {dependencyReady
              ? "A dependência necessária está disponível. A tela não inventa métricas ou resultados: dados operacionais serão exibidos somente quando fornecidos pelo contrato real da API."
              : "A dependência necessária está indisponível. O módulo mantém o estado explícito e não simula sucesso, dispositivos, métricas ou execução."}
          </p>
        </div>
      </section>
    </div>
  );
}
