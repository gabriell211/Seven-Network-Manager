import { getSystemStatus } from "@/src/lib/api";

const modules = [
  ["Inventário", "Ativos, interfaces e identidade técnica"],
  ["IPAM", "IPv4, IPv6 e routing domains sem colisões falsas"],
  ["Discovery", "Descoberta executada no runtime local"],
  ["Telemetria", "SNMP, checks e eventos operacionais"],
];

export default async function Home() {
  const system = await getSystemStatus();

  return (
    <main className="mx-auto min-h-screen max-w-7xl px-6 py-10 lg:px-10">
      <header className="flex flex-col gap-6 border-b border-[var(--border)] pb-8 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="mb-3 text-sm font-semibold tracking-[0.2em] text-sky-400">SEVEN / CONTROL PLANE</p>
          <h1 className="text-4xl font-semibold tracking-tight lg:text-5xl">Network Manager</h1>
          <p className="mt-4 max-w-2xl text-base leading-7 text-[var(--muted)]">
            Administração de infraestrutura com execução LAN isolada do control plane e contexto explícito de site e routing domain.
          </p>
        </div>
        <div className="rounded-xl border border-[var(--border)] bg-[var(--panel)] px-5 py-4">
          <p className="text-xs uppercase tracking-wider text-[var(--muted)]">Backend</p>
          <p className="mt-1 font-medium">{system ? `online · v${system.version}` : "indisponível"}</p>
        </div>
      </header>

      <section className="grid gap-4 py-8 md:grid-cols-2 xl:grid-cols-4">
        {modules.map(([title, description]) => (
          <article key={title} className="rounded-2xl border border-[var(--border)] bg-[var(--panel)] p-5">
            <div className="mb-8 h-2 w-2 rounded-full bg-sky-400" />
            <h2 className="text-lg font-semibold">{title}</h2>
            <p className="mt-2 text-sm leading-6 text-[var(--muted)]">{description}</p>
          </article>
        ))}
      </section>

      <section className="rounded-2xl border border-[var(--border)] bg-[var(--panel-strong)] p-6">
        <p className="text-xs uppercase tracking-wider text-[var(--muted)]">Deployment</p>
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <Status label="Control plane" value={system ? "healthy" : "offline"} />
          <Status label="Runtime placement" value="site-local / headless" />
          <Status label="Mode" value={system?.deploymentMode ?? "production-mvp-onprem"} />
        </div>
      </section>
    </main>
  );
}

function Status({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-1 font-medium">{value}</p>
    </div>
  );
}
