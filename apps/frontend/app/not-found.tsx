import Link from "next/link";

import { Icon } from "@/src/components/icon";

export default function NotFound() {
  return (
    <div className="state-page">
      <section className="state-card">
        <div className="state-card__icon"><Icon name="network" size={25} /></div>
        <h1>Rota não encontrada</h1>
        <p>Esta área não existe no Seven Network Manager. Volte ao dashboard para acessar os módulos disponíveis.</p>
        <Link className="button button--secondary" href="/">Voltar ao dashboard</Link>
      </section>
    </div>
  );
}
