"use client";

import { useEffect } from "react";

import { Icon } from "@/src/components/icon";

export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error("frontend route failure", error);
  }, [error]);

  return (
    <div className="state-page">
      <section className="state-card" role="alert">
        <div className="state-card__icon"><Icon name="warning" size={25} /></div>
        <h1>Não foi possível carregar esta área</h1>
        <p>
          O erro foi mantido explícito. Nenhum dado de demonstração foi usado para substituir uma resposta operacional ausente.
        </p>
        <button className="button button--secondary" onClick={reset} type="button">
          <Icon name="refresh" size={17} />
          Tentar novamente
        </button>
      </section>
    </div>
  );
}
