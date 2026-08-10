import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { Icon } from "@/src/components/icon";
import { OperationalIcon } from "@/src/components/operational-icon";
import { getOperationalContext, listDevices, listIpamPrefixes } from "@/src/lib/session";

import { createAddressAction } from "../actions";

export const metadata: Metadata = { title: "Nova alocação IPAM" };

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function NewAddressPage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const context = await getOperationalContext();
  if (!context.ok) {
    if (context.status === 401) redirect("/login");
    return <State title="Contexto indisponível" message={context.error.message} />;
  }
  const site = context.data.sites.find((candidate) => candidate.id === scalar(params.site) && candidate.permissions.includes("ipam.create")) ?? context.data.sites.find((candidate) => candidate.permissions.includes("ipam.create"));
  if (!site) return <State title="Permissão insuficiente" message="Nenhum site acessível concede ipam.create." />;
  const routingDomain = site.routingDomains.find((domain) => domain.id === scalar(params.routingDomain)) ?? site.defaultRoutingDomain ?? site.routingDomains[0];
  if (!routingDomain) return <State title="Routing domain ausente" message="O site não possui contexto L3 para receber alocações." />;

  const [prefixes, devices] = await Promise.all([
    listIpamPrefixes(site.id, routingDomain.id),
    site.permissions.includes("devices.view") ? listDevices(site.id, { limit: 200, offset: 0 }) : Promise.resolve(null),
  ]);
  if (!prefixes.ok) return <State title="Prefixos indisponíveis" message={prefixes.error.message} />;
  if (prefixes.data.length === 0) {
    return <State title="Nenhum prefixo disponível" message="Cadastre um prefixo real neste routing domain antes de reservar ou atribuir um endereço." />;
  }
  const deviceRows = devices?.ok ? devices.data : [];

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div><span className="eyebrow">IPAM · {site.name} · {routingDomain.name}</span><h1>Nova alocação</h1><p>O endereço precisa pertencer ao prefixo selecionado. IPv6 link-local exige interface/scope explícito.</p></div>
        <Link className="button button--secondary" href={`/ipam?site=${site.id}&routingDomain=${routingDomain.id}`}>Voltar ao IPAM</Link>
      </section>
      {scalar(params.error) ? <div className="form-error" role="alert">Falha: {scalar(params.error)}</div> : null}
      <form action={createAddressAction} className="device-form">
        <input name="siteId" type="hidden" value={site.id} /><input name="routingDomainId" type="hidden" value={routingDomain.id} />
        <section className="form-section">
          <div className="form-section__heading"><Icon name="ipam" size={21} /><div><h2>Endereço e prefixo</h2><p>A API valida família, prefixo, routing domain e conflitos no escopo correto.</p></div></div>
          <div className="form-grid">
            <label className="field"><span className="field__label">Prefixo</span><select defaultValue={scalar(params.prefix) ?? prefixes.data[0]?.id} name="prefixId" required>{prefixes.data.map((prefix) => <option key={prefix.id} value={prefix.id}>{prefix.prefix}{prefix.name ? ` · ${prefix.name}` : ""}</option>)}</select></label>
            <label className="field"><span className="field__label">Endereço</span><input autoComplete="off" name="address" placeholder="10.20.0.10 ou 2001:db8::10" required /></label>
            <label className="field"><span className="field__label">Estado</span><select defaultValue="reserved" name="state"><option value="reserved">Reservado</option><option value="assigned">Atribuído</option><option value="observed">Observado</option><option value="conflict">Conflito</option><option value="excluded">Excluído</option></select></label>
            <label className="field"><span className="field__label">Origem</span><input defaultValue="manual" name="source" required /></label>
          </div>
        </section>
        <section className="form-section">
          <div className="form-section__heading"><OperationalIcon name="hostname" size={20} /><div><h2>Vínculos</h2><p>O vínculo é opcional, mas quando existir aponta para IDs reais do inventário.</p></div></div>
          <div className="form-grid">
            <label className="field"><span className="field__label">Dispositivo</span><select defaultValue="" name="deviceId"><option value="">Sem vínculo</option>{deviceRows.map((device) => <option key={device.id} value={device.id}>{device.displayName ?? device.hostname ?? device.serialNumber ?? device.id}</option>)}</select></label>
            <label className="field"><span className="field__label">Interface ID</span><input autoComplete="off" name="interfaceId" placeholder="UUID da interface; obrigatório para fe80::/10" /></label>
            <label className="field"><span className="field__label">DNS</span><input autoComplete="off" name="dnsName" placeholder="host.exemplo.local" /></label>
            <label className="field field--wide"><span className="field__label">Descrição</span><textarea name="description" rows={4} /></label>
          </div>
        </section>
        <div className="form-actions"><Link className="button button--secondary" href={`/ipam?site=${site.id}&routingDomain=${routingDomain.id}`}>Cancelar</Link><button className="button button--primary" type="submit"><OperationalIcon name="plus" size={17} />Criar alocação</button></div>
      </form>
    </div>
  );
}

function State({ title, message }: { title: string; message: string }) { return <section className="operational-state operational-state--error"><span className="operational-state__icon"><OperationalIcon name="lock" size={22} /></span><div><h1>{title}</h1><p>{message}</p></div></section>; }
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }
