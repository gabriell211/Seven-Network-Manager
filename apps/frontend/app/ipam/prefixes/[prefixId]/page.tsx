import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { Icon } from "@/src/components/icon";
import { OperationalIcon } from "@/src/components/operational-icon";
import { getOperationalContext, listIpamPrefixes } from "@/src/lib/session";

import { deletePrefixAction, updatePrefixAction } from "../../actions";

export const metadata: Metadata = { title: "Editar prefixo IPAM" };

type PageParams = Promise<{ prefixId: string }>;
type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function EditPrefixPage({ params, searchParams }: { params: PageParams; searchParams: SearchParams }) {
  const [{ prefixId }, query] = await Promise.all([params, searchParams]);
  const context = await getOperationalContext();
  if (!context.ok) {
    if (context.status === 401) redirect("/login");
    return <State title="Contexto indisponível" message={context.error.message} />;
  }
  const site = context.data.sites.find((candidate) => candidate.id === scalar(query.site) && candidate.permissions.includes("ipam.view")) ?? context.data.sites.find((candidate) => candidate.permissions.includes("ipam.view"));
  if (!site) return <State title="Site indisponível" message="A sessão não possui acesso ao site deste prefixo." />;

  const prefixes = await listIpamPrefixes(site.id);
  if (!prefixes.ok) {
    if (prefixes.status === 401) redirect("/login");
    return <State title="Prefixo indisponível" message={prefixes.error.message} />;
  }
  const prefix = prefixes.data.find((candidate) => candidate.id === prefixId);
  if (!prefix) notFound();
  const routingDomain = site.routingDomains.find((domain) => domain.id === prefix.routingDomainId);
  const canUpdate = site.permissions.includes("ipam.update");
  const canDelete = site.permissions.includes("ipam.delete");

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div><span className="eyebrow">IPAM · {site.name}</span><h1>{prefix.prefix}</h1><p>{prefix.name ?? "Prefixo sem nome"} · versão {prefix.version}</p></div>
        <Link className="button button--secondary" href={`/ipam?site=${site.id}&routingDomain=${prefix.routingDomainId}`}>Voltar ao IPAM</Link>
      </section>
      {scalar(query.saved) === "1" ? <div className="form-success" role="status">Prefixo atualizado e auditado.</div> : null}
      {scalar(query.error) ? <div className="form-error" role="alert">Falha: {scalar(query.error)}</div> : null}

      <section className="context-bar">
        <div><span className="eyebrow">Routing domain</span><strong>{routingDomain?.name ?? prefix.routingDomainId}</strong></div>
        <div><span className="eyebrow">Alocações</span><strong>{prefix.capacity.allocatedAddresses}</strong></div>
        <div><span className="eyebrow">Capacidade total</span><strong>{prefix.capacity.totalAddresses}</strong></div>
        <div><span className="eyebrow">Utilização</span><strong>{new Intl.NumberFormat("pt-BR", { maximumFractionDigits: 2 }).format(prefix.capacity.utilizationPercent)}%</strong></div>
      </section>

      {canUpdate ? (
        <form action={updatePrefixAction} className="device-form">
          <input name="siteId" type="hidden" value={site.id} /><input name="prefixId" type="hidden" value={prefix.id} /><input name="expectedVersion" type="hidden" value={prefix.version} />
          <section className="form-section">
            <div className="form-section__heading"><Icon name="ipam" size={21} /><div><h2>Endereçamento</h2><p>Alterações que gerem overlap na mesma VRF são recusadas pelo banco.</p></div></div>
            <div className="form-grid">
              <label className="field"><span className="field__label">Routing domain</span><select defaultValue={prefix.routingDomainId} name="routingDomainId">{site.routingDomains.map((domain) => <option key={domain.id} value={domain.id}>{domain.name}{domain.isDefault ? " · default" : ""}</option>)}</select></label>
              <label className="field"><span className="field__label">CIDR</span><input defaultValue={prefix.prefix} name="prefix" required /></label>
              <label className="field"><span className="field__label">Gateway</span><input defaultValue={prefix.gateway ?? ""} name="gateway" /></label>
              <label className="field"><span className="field__label">VLAN ID</span><input defaultValue={prefix.vlanId ?? ""} max="4094" min="1" name="vlanId" type="number" /></label>
            </div>
          </section>
          <section className="form-section">
            <div className="form-section__heading"><OperationalIcon name="edit" size={20} /><div><h2>Contexto administrativo</h2><p>Os campos continuam declarados e versionados.</p></div></div>
            <div className="form-grid">
              <label className="field"><span className="field__label">Nome</span><input defaultValue={prefix.name ?? ""} name="name" /></label>
              <label className="field"><span className="field__label">Finalidade</span><input defaultValue={prefix.purpose ?? ""} name="purpose" /></label>
              <label className="field field--wide"><span className="field__label">Descrição</span><textarea defaultValue={prefix.description ?? ""} name="description" rows={4} /></label>
            </div>
          </section>
          <div className="form-actions"><button className="button button--primary" type="submit"><OperationalIcon name="edit" size={17} />Salvar prefixo</button></div>
        </form>
      ) : <State title="Somente leitura" message="Sua sessão possui ipam.view, mas não ipam.update neste site." />}

      {canDelete ? (
        <section className="danger-zone">
          <div><span className="eyebrow">Operação destrutiva</span><h2>Remover prefixo</h2><p>A remoção falha se existirem alocações dependentes. Não existe cascade silencioso.</p></div>
          <form action={deletePrefixAction}><input name="siteId" type="hidden" value={site.id} /><input name="resourceId" type="hidden" value={prefix.id} /><input name="expectedVersion" type="hidden" value={prefix.version} /><input name="returnTo" type="hidden" value={`/ipam?site=${site.id}&routingDomain=${prefix.routingDomainId}`} /><button className="button button--danger" type="submit"><OperationalIcon name="retire" size={17} />Remover prefixo</button></form>
        </section>
      ) : null}
    </div>
  );
}

function State({ title, message }: { title: string; message: string }) { return <section className="operational-state"><span className="operational-state__icon"><OperationalIcon name="lock" size={22} /></span><div><h2>{title}</h2><p>{message}</p></div></section>; }
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }
