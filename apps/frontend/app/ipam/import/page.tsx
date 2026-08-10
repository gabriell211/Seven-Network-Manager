import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { Icon } from "@/src/components/icon";
import { IpamImportForm } from "@/src/components/ipam-import-form";
import { OperationalIcon } from "@/src/components/operational-icon";
import { getOperationalContext } from "@/src/lib/session";

export const metadata: Metadata = { title: "Importar IPAM" };

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function ImportIpamPage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const context = await getOperationalContext();
  if (!context.ok) {
    if (context.status === 401) redirect("/login");
    return <State title="Contexto indisponível" message={context.error.message} />;
  }
  const site = context.data.sites.find((candidate) => candidate.id === scalar(params.site) && candidate.permissions.includes("ipam.create")) ?? context.data.sites.find((candidate) => candidate.permissions.includes("ipam.create"));
  if (!site) return <State title="Permissão insuficiente" message="Nenhum site acessível concede ipam.create." />;
  const routingDomain = site.routingDomains.find((domain) => domain.id === scalar(params.routingDomain)) ?? site.defaultRoutingDomain ?? site.routingDomains[0];
  if (!routingDomain) return <State title="Routing domain ausente" message="Selecione um site que possua contexto L3." />;

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div><span className="eyebrow">IPAM · importação validada</span><h1>Importar CSV</h1><p>Cada linha é enviada ao mesmo contrato e às mesmas constraints usadas pela UI normal. Erros retornam por linha; sucesso parcial nunca é apresentado como importação total.</p></div>
        <Link className="button button--secondary" href={`/ipam?site=${site.id}&routingDomain=${routingDomain.id}`}>Voltar ao IPAM</Link>
      </section>

      <section className="context-bar">
        <div><span className="eyebrow">Site</span><strong>{site.name}</strong></div>
        <div><span className="eyebrow">Routing domain</span><strong>{routingDomain.name}</strong></div>
        <div><span className="eyebrow">Limite</span><strong>5.000 linhas</strong></div>
        <div><span className="eyebrow">Tamanho máximo</span><strong>2 MiB</strong></div>
      </section>

      <section className="section-block">
        <div className="section-heading"><div><span className="eyebrow">Arquivo não confiável</span><h2>Validação e aplicação</h2></div><span className="section-heading__note">Mutations continuam auditadas individualmente</span></div>
        <IpamImportForm routingDomainId={routingDomain.id} siteId={site.id} />
      </section>

      <section className="section-block">
        <div className="section-heading"><div><span className="eyebrow">Formato</span><h2>Colunas aceitas</h2></div><a className="button button--secondary" href={`/api/ipam/export?site=${site.id}&routingDomain=${routingDomain.id}`}><OperationalIcon name="archive" size={17} />Exportar CSV atual</a></div>
        <div className="schema-grid">
          {["recordType", "routingDomainId", "prefixId", "prefix", "address", "state", "name", "gateway", "vlanId", "purpose", "dnsName", "source", "deviceId", "interfaceId", "description"].map((field) => <span className="schema-chip" key={field}><Icon name="settings" size={14} /><code>{field}</code></span>)}
        </div>
        <p className="section-copy">Use <code>recordType=prefix</code> para blocos CIDR e <code>recordType=address</code> para alocações. O routingDomainId do arquivo, quando informado, precisa coincidir com o escopo escolhido nesta tela. O estado <code>available</code> não é importável porque disponibilidade é derivada do prefixo.</p>
      </section>
    </div>
  );
}

function State({ title, message }: { title: string; message: string }) { return <section className="operational-state operational-state--error"><span className="operational-state__icon"><OperationalIcon name="lock" size={22} /></span><div><h1>{title}</h1><p>{message}</p></div></section>; }
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }
