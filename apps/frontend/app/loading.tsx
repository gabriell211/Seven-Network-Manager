export default function Loading() {
  return (
    <div aria-busy="true" aria-label="Carregando dados operacionais" className="page-stack" role="status">
      <section className="page-heading">
        <div className="skeleton-wrap">
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
