import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { Icon } from "@/src/components/icon";
import { OperationalIcon } from "@/src/components/operational-icon";
import { getOperationalContext } from "@/src/lib/session";

import { createPrefixAction } from "../actions";

export const metadata: Metadata = { title: "Novo prefixo IPAM" };

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function NewPrefixPage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const context = await getOperationalContext();
  if (!context.ok) {
    if (context.status === 401) redirect("/login");
    return <State title="Contexto indisponível" message={context.error.message} />;
  }
  const site = context.data.sites.find((candidate) => candidate.id === scalar(params.site) && candidate.permissions.includes("ipam.create")) ?? context.data.sites.find((candidate) => candidate.permissions.includes("ipam.create"));
  if (!site) return <State title="Permissão insuficiente" message="Nenhum site acessível concede ipam.create." />;
  const routingDomain = site.routingDomains.find((domain) => domain.id === scalar(params.routingDomain)) ?? site.defaultRoutingDomain ?? site.routingDomains[0];
  if (!routingDomain) return <State title="Routing domain ausente" message="Cadastre ou restaure um routing domain para este site antes do IPAM." />;

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div><span className="eyebrow">IPAM · {site.name}</span><h1>Novo prefixo</h1><p>O CIDR será validado pelo domínio e pelo PostgreSQL. Overlaps só são bloqueados dentro do mesmo routing domain.</p></div>
        <Link className="button button--secondary" href={`/ipam?site=${site.id}&routingDomain=${routingDomain.id}`}>Voltar ao IPAM</Link>
      </section>
      {scalar(params.error) ? <div className="form-error" role="alert">Falha: {scalar(params.error)}</div> : null}
      <form action={createPrefixAction} className="device-form">
        <input name="siteId" type="hidden" value={site.id} />
        <section className="form-section">
          <div className="form-section__heading"><Icon name="ipam" size={21} /><div><h2>Endereçamento</h2><p>IPv4 e IPv6 são tratados como prefixos estruturados, nunca como comparação textual ingênua.</p></div></div>
          <div className="form-grid">
            <label className="field"><span className="field__label">Routing domain</span><select defaultValue={routingDomain.id} name="routingDomainId">{site.routingDomains.map((domain) => <option key={domain.id} value={domain.id}>{domain.name}{domain.isDefault ? " · default" : ""}</option>)}</select></label>
            <label className="field"><span className="field__label">CIDR</span><input autoComplete="off" name="prefix" placeholder="10.20.0.0/24 ou 2001:db8:10::/64" required /></label>
            <label className="field"><span className="field__label">Gateway</span><input autoComplete="off" name="gateway" placeholder="Opcional, deve pertencer ao prefixo" /></label>
            <label className="field"><span className="field__label">VLAN ID</span><input inputMode="numeric" max="4094" min="1" name="vlanId" placeholder="Opcional" type="number" /></label>
          </div>
        </section>
        <section className="form-section">
          <div className="form-section__heading"><OperationalIcon name="edit" size={20} /><div><h2>Contexto administrativo</h2><p>Descrição e finalidade são dados declarados, não inferidos pelo discovery.</p></div></div>
          <div className="form-grid">
            <label className="field"><span className="field__label">Nome</span><input name="name" /></label>
            <label className="field"><span className="field__label">Finalidade</span><input name="purpose" placeholder="Usuários, servidores, impressoras…" /></label>
            <label className="field field--wide"><span className="field__label">Descrição</span><textarea name="description" rows={4} /></label>
          </div>
        </section>
        <div className="form-actions"><Link className="button button--secondary" href={`/ipam?site=${site.id}&routingDomain=${routingDomain.id}`}>Cancelar</Link><button className="button button--primary" type="submit"><OperationalIcon name="plus" size={17} />Criar prefixo</button></div>
      </form>
    </div>
  );
}

function State({ title, message }: { title: string; message: string }) { return <section className="operational-state operational-state--error"><span className="operational-state__icon"><OperationalIcon name="lock" size={22} /></span><div><h1>{title}</h1><p>{message}</p></div></section>; }
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }
