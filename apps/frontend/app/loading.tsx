export default function Loading() {
  return (
    <div aria-busy="true" aria-label="Carregando dados operacionais" className="page-stack" role="status">
      <section className="page-heading">
        <div style={{ width: "100%" }}>
          <div className="skeleton skeleton--title" />
          <div className="skeleton skeleton--line" />
        </div>
      </section>
      <div className="skeleton-grid">
        <div className="skeleton skeleton--card" />
        <div className="skeleton skeleton--card" />
        <div className="skeleton skeleton--card" />
        <div className="skeleton skeleton--card" />
      </div>
    </div>
  );
}
