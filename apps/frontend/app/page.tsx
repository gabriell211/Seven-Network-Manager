const modules = [
  { name: "Inventario", state: "Foundation", detail: "Modelo pronto para discovery, lifecycle e evidencias." },
  { name: "Runtime local", state: "Foundation", detail: "Executor headless separado do control plane e da UI." },
  { name: "Capabilities", state: "Foundation", detail: "Contratos para providers, transports e placement." },
  { name: "Trial", state: "Release", detail: "Preparado para piloto controlado sem liberar operacao irrestrita." },
];

export default function Page() {
  return (
    <main className="shell">
      <section className="hero">
        <div>
          <p className="eyebrow">Seven Network Manager</p>
          <h1>Control plane on-premise para redes corporativas.</h1>
          <p className="lede">
            Inventario, discovery, IPAM, SNMP, operacao segura e trial controlado nascendo sobre uma arquitetura modular.
          </p>
        </div>
        <div className="statusPanel" aria-label="Status do sistema">
          <span className="statusDot" />
          <strong>FOUNDATION C0/C1</strong>
          <small>Backend, runtime, dominio, Docker e UI base</small>
        </div>
      </section>

      <section className="grid" aria-label="Modulos">
        {modules.map((module) => (
          <article className="module" key={module.name}>
            <span>{module.state}</span>
            <h2>{module.name}</h2>
            <p>{module.detail}</p>
          </article>
        ))}
      </section>
    </main>
  );
}
