import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { Icon } from "@/src/components/icon";
import { OperationalIcon } from "@/src/components/operational-icon";
import { getOperationalContext, listDevices, listIpamAddresses } from "@/src/lib/session";

import { deleteAddressAction, updateAddressAction } from "../../actions";

export const metadata: Metadata = { title: "Editar alocação IPAM" };

type PageParams = Promise<{ addressId: string }>;
type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function EditAddressPage({ params, searchParams }: { params: PageParams; searchParams: SearchParams }) {
  const [{ addressId }, query] = await Promise.all([params, searchParams]);
  const context = await getOperationalContext();
  if (!context.ok) {
    if (context.status === 401) redirect("/login");
    return <State title="Contexto indisponível" message={context.error.message} />;
  }
  const site = context.data.sites.find((candidate) => candidate.id === scalar(query.site) && candidate.permissions.includes("ipam.view")) ?? context.data.sites.find((candidate) => candidate.permissions.includes("ipam.view"));
  if (!site) return <State title="Site indisponível" message="A sessão não possui acesso ao site desta alocação." />;
  const routingDomain = site.routingDomains.find((domain) => domain.id === scalar(query.routingDomain)) ?? site.defaultRoutingDomain ?? site.routingDomains[0];
  if (!routingDomain) return <State title="Routing domain ausente" message="O contexto L3 desta alocação não está disponível." />;

  const [addresses, devices] = await Promise.all([
    listIpamAddresses(site.id, { routingDomainId: routingDomain.id, search: scalar(query.address), limit: 200, offset: 0 }),
    site.permissions.includes("devices.view") ? listDevices(site.id, { limit: 200, offset: 0 }) : Promise.resolve(null),
  ]);
  if (!addresses.ok) {
    if (addresses.status === 401) redirect("/login");
    return <State title="Alocação indisponível" message={addresses.error.message} />;
  }
  const address = addresses.data.find((candidate) => candidate.id === addressId);
  if (!address) notFound();
  const deviceRows = devices?.ok ? devices.data : [];
  const canUpdate = site.permissions.includes("ipam.update");
  const canDelete = site.permissions.includes("ipam.delete");

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div><span className="eyebrow">IPAM · {site.name} · {routingDomain.name}</span><h1>{address.address}</h1><p>{address.dnsName ?? "Sem DNS"} · versão {address.version}</p></div>
        <Link className="button button--secondary" href={`/ipam?site=${site.id}&routingDomain=${routingDomain.id}`}>Voltar ao IPAM</Link>
      </section>
      {scalar(query.saved) === "1" ? <div className="form-success" role="status">Alocação atualizada e auditada.</div> : null}
      {scalar(query.error) ? <div className="form-error" role="alert">Falha: {scalar(query.error)}</div> : null}

      <section className="device-overview">
        <Overview icon="ipam" label="Endereço" value={address.address} />
        <Overview icon="ipam" label="Estado" value={stateLabel(address.state)} />
        <Overview icon="inventory" label="Dispositivo" value={address.deviceId ?? "Sem vínculo"} />
        <Overview icon="settings" label="Origem" value={address.source} />
      </section>

      {canUpdate ? (
        <form action={updateAddressAction} className="device-form">
          <input name="siteId" type="hidden" value={site.id} /><input name="routingDomainId" type="hidden" value={routingDomain.id} /><input name="prefixId" type="hidden" value={address.prefixId ?? ""} /><input name="address" type="hidden" value={address.address} /><input name="addressId" type="hidden" value={address.id} /><input name="expectedVersion" type="hidden" value={address.version} />
          <section className="form-section">
            <div className="form-section__heading"><Icon name="ipam" size={21} /><div><h2>Estado e origem</h2><p>O endereço/prefixo não é movido silenciosamente. Para mudar identidade L3, remova e crie uma nova alocação no contexto correto.</p></div></div>
            <div className="form-grid">
              <label className="field"><span className="field__label">Estado</span><select defaultValue={address.state === "available" ? "reserved" : address.state} name="state"><option value="reserved">Reservado</option><option value="assigned">Atribuído</option><option value="observed">Observado</option><option value="conflict">Conflito</option><option value="excluded">Excluído</option></select></label>
              <label className="field"><span className="field__label">Origem</span><input defaultValue={address.source} name="source" required /></label>
            </div>
          </section>
          <section className="form-section">
            <div className="form-section__heading"><OperationalIcon name="hostname" size={20} /><div><h2>Vínculos</h2><p>Vínculos permanecem escopados ao mesmo site.</p></div></div>
            <div className="form-grid">
              <label className="field"><span className="field__label">Dispositivo</span><select defaultValue={address.deviceId ?? ""} name="deviceId"><option value="">Sem vínculo</option>{deviceRows.map((device) => <option key={device.id} value={device.id}>{device.displayName ?? device.hostname ?? device.serialNumber ?? device.id}</option>)}</select></label>
              <label className="field"><span className="field__label">Interface ID</span><input defaultValue={address.interfaceId ?? ""} name="interfaceId" placeholder="Obrigatório para IPv6 link-local" /></label>
              <label className="field"><span className="field__label">DNS</span><input defaultValue={address.dnsName ?? ""} name="dnsName" /></label>
              <label className="field field--wide"><span className="field__label">Descrição</span><textarea defaultValue={address.description ?? ""} name="description" rows={4} /></label>
            </div>
          </section>
          <div className="form-actions"><button className="button button--primary" type="submit"><OperationalIcon name="edit" size={17} />Salvar alocação</button></div>
        </form>
      ) : <State title="Somente leitura" message="Sua sessão possui ipam.view, mas não ipam.update neste site." />}

      {canDelete ? (
        <section className="danger-zone"><div><span className="eyebrow">Operação destrutiva</span><h2>Remover alocação</h2><p>A remoção usa optimistic version e gera auditoria/Outbox na mesma transação.</p></div><form action={deleteAddressAction}><input name="siteId" type="hidden" value={site.id} /><input name="resourceId" type="hidden" value={address.id} /><input name="expectedVersion" type="hidden" value={address.version} /><input name="returnTo" type="hidden" value={`/ipam?site=${site.id}&routingDomain=${routingDomain.id}`} /><button className="button button--danger" type="submit"><OperationalIcon name="retire" size={17} />Remover alocação</button></form></section>
      ) : null}
    </div>
  );
}

function Overview({ icon, label, value }: { icon: "ipam" | "inventory" | "settings"; label: string; value: string }) { return <div className="overview-item"><Icon name={icon} size={18} /><div><span>{label}</span><strong>{value}</strong></div></div>; }
function State({ title, message }: { title: string; message: string }) { return <section className="operational-state"><span className="operational-state__icon"><OperationalIcon name="lock" size={22} /></span><div><h2>{title}</h2><p>{message}</p></div></section>; }
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }
function stateLabel(value: string) { return ({ available: "Disponível", reserved: "Reservado", assigned: "Atribuído", observed: "Observado", conflict: "Conflito", excluded: "Excluído" } as Record<string, string>)[value] ?? value; }
