import type { Metadata } from "next";
import Link from "next/link";

import spec from "../../public/openapi-v1.json";

import { Icon } from "@/src/components/icon";
import { OperationalIcon } from "@/src/components/operational-icon";

export const metadata: Metadata = { title: "Contrato REST" };

const httpMethods = new Set(["get", "post", "put", "patch", "delete"]);

export default function ApiDocsPage() {
  const operations = Object.entries(spec.paths).flatMap(([path, pathItem]) =>
    Object.entries(pathItem)
      .filter(([method]) => httpMethods.has(method))
      .map(([method, operation]) => ({
        method: method.toUpperCase(),
        path,
        operationId:
          typeof operation === "object" && operation !== null && "operationId" in operation
            ? String(operation.operationId)
            : "sem operationId",
      })),
  );
  const schemas = Object.keys(spec.components.schemas).sort();

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div>
          <span className="eyebrow">OpenAPI {spec.openapi}</span>
          <h1>{spec.info.title}</h1>
          <p>{spec.info.description}</p>
        </div>
        <Link className="button button--secondary" href="/openapi-v1.json" target="_blank">
          <OperationalIcon name="archive" size={17} />
          Abrir especificação JSON
        </Link>
      </section>

      <section className="context-bar" aria-label="Resumo do contrato">
        <div><span className="eyebrow">Versão API</span><strong>{spec.info.version}</strong></div>
        <div><span className="eyebrow">Base</span><strong>{spec.servers[0]?.url ?? "/api/v1"}</strong></div>
        <div><span className="eyebrow">Operações</span><strong>{operations.length}</strong></div>
        <div><span className="eyebrow">Schemas</span><strong>{schemas.length}</strong></div>
      </section>

      <section className="section-block">
        <div className="section-heading">
          <div><span className="eyebrow">Operações publicadas</span><h2>Rotas do contrato versionado</h2></div>
          <span className="section-heading__note">Gerado da mesma especificação usada pelo TypeScript</span>
        </div>
        <div className="api-operation-list">
          {operations.map((operation) => (
            <article className="api-operation" key={`${operation.method}:${operation.path}`}>
              <span className="api-method" data-method={operation.method}>{operation.method}</span>
              <code>{operation.path}</code>
              <span>{operation.operationId}</span>
            </article>
          ))}
        </div>
      </section>

      <section className="section-block">
        <div className="section-heading">
          <div><span className="eyebrow">Schemas</span><h2>Tipos públicos</h2></div>
        </div>
        <div className="schema-grid">
          {schemas.map((schema) => (
            <div className="schema-chip" key={schema}>
              <Icon name="settings" size={15} />
              <code>{schema}</code>
            </div>
          ))}
        </div>
      </section>

      <section className="boundary-card">
        <div className="boundary-card__icon"><Icon name="shield" size={24} /></div>
        <div>
          <span className="eyebrow">Contrato, não executor</span>
          <h2>A documentação descreve o control plane</h2>
          <p>Operações LAN continuam atrás do site-runtime. A existência de uma rota HTTP nunca autoriza o navegador a executar transportes de rede diretamente.</p>
        </div>
      </section>
    </div>
  );
}
