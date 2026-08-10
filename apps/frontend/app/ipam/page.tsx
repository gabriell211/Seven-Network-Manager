import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import type { AddressState, IpPrefix, RoutingDomain, SiteContext } from "@/src/generated/api-contract";
import { Icon } from "@/src/components/icon";
import { OperationalIcon } from "@/src/components/operational-icon";
import { getOperationalContext, listIpamAddresses, listIpamPrefixes } from "@/src/lib/session";

import { deleteAddressAction, deletePrefixAction } from "./actions";

export const metadata: Metadata = { title: "IPAM" };

const stateOptions: ReadonlyArray<{ value: AddressState; label: string }> = [
  { value: "reserved", label: "Reservado" },
  { value: "assigned", label: "Atribuído" },
  { value: "observed", label: "Observado" },
  { value: "conflict", label: "Conflito" },
  { value: "excluded", label: "Excluído" },
];

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function IpamPage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const context = await getOperationalContext();
  if (!context.ok) {
    if (context.status === 401) redirect("/login");
    return <IpamState title="IPAM indisponível" message={context.error.message} error />;
  }

  const site = selectSite(context.data.sites, scalar(params.site));
  if (!site) {
    return <IpamState title="Nenhum site acessível" message="A sessão não possui um site autorizado para IPAM." />;
  }
  if (!site.permissions.includes("ipam.view")) {
    return <IpamState title="Permissão insuficiente" message="Sua sessão não possui ipam.view neste site." error />;
  }

  const routingDomain = selectRoutingDomain(site, scalar(params.routingDomain));
  if (!routingDomain) {
    return <IpamState title="Routing domain ausente" message="O site precisa possuir ao menos um routing domain antes de cadastrar prefixos." />;
  }

  const prefixId = scalar(params.prefix) || undefined;
  const search = scalar(params.search)?.trim() || undefined;
  const state = asState(scalar(params.state));
  const offset = nonNegativeInteger(scalar(params.offset));
  const [prefixes, addresses] = await Promise.all([
    listIpamPrefixes(site.id, routingDomain.id),
    listIpamAddresses(site.id, {
      routingDomainId: routingDomain.id,
      prefixId,
      state,
      search,
      limit: 100,
      offset,
    }),
  ]);

  if (!prefixes.ok) {
    if (prefixes.status === 401) redirect("/login");
    return <IpamState title="Prefixos indisponíveis" message={prefixes.error.message} error />;
  }
  if (!addresses.ok) {
    if (addresses.status === 401) redirect("/login");
    return <IpamState title="Alocações indisponíveis" message={addresses.error.message} error />;
  }

  const canCreate = site.permissions.includes("ipam.create");
  const canUpdate = site.permissions.includes("ipam.update");
  const canDelete = site.permissions.includes("ipam.delete");
  const allocatedTotal = prefixes.data.reduce((total, prefix) => total + prefix.capacity.allocatedAddresses, 0);
  const conflictTotal = addresses.data.filter((address) => address.state === "conflict").length;

  return (
    <div className="page-stack">
      <section className="page-heading inventory-heading">
        <div>
          <span className="eyebrow">Network Addressing</span>
          <h1>IPAM IPv4 / IPv6</h1>
          <p>Prefixos e alocações persistidos por site e routing domain. Overlap legítimo entre VRFs é permitido; conflito dentro da mesma VRF é bloqueado no PostgreSQL.</p>
        </div>
        {canCreate ? (
          <div className="page-actions">
            <Link className="button button--secondary" href={`/ipam/new-address?site=${site.id}&routingDomain=${routingDomain.id}`}>
              <OperationalIcon name="plus" size={17} />Endereço
            </Link>
            <Link className="button button--primary" href={`/ipam/new-prefix?site=${site.id}&routingDomain=${routingDomain.id}`}>
              <OperationalIcon name="plus" size={17} />Prefixo
            </Link>
          </div>
        ) : null}
      </section>

      {scalar(params.saved) ? <div className="form-success" role="status">Alteração confirmada pelo control plane.</div> : null}
      {scalar(params.deleted) ? <div className="form-success" role="status">Recurso removido e auditado.</div> : null}
      {scalar(params.error) ? <div className="form-error" role="alert">Falha: {scalar(params.error)}</div> : null}

      <section className="context-bar" aria-label="Contexto IPAM">
        <div><span className="eyebrow">Site</span><strong>{site.name}</strong></div>
        <div><span className="eyebrow">Routing domain</span><strong>{routingDomain.name}</strong></div>
        <div><span className="eyebrow">Prefixos</span><strong>{prefixes.data.length}</strong></div>
        <div><span className="eyebrow">Alocações carregadas</span><strong>{allocatedTotal}</strong></div>
      </section>

      <form className="inventory-filters" method="get">
        <label className="field field--search">
          <span className="field__label">Buscar endereço / DNS</span>
          <span className="field__control"><OperationalIcon name="search" size={18} /><input defaultValue={search} name="search" placeholder="2001:db8::10, 10.0.0.10 ou hostname" /></span>
        </label>
        <label className="field"><span className="field__label">Site</span><select defaultValue={site.id} name="site">{context.data.sites.filter((item) => item.permissions.includes("ipam.view")).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        <label className="field"><span className="field__label">Routing domain</span><select defaultValue={routingDomain.id} name="routingDomain">{site.routingDomains.map((domain) => <option key={domain.id} value={domain.id}>{domain.name}{domain.isDefault ? " · default" : ""}</option>)}</select></label>
        <label className="field"><span className="field__label">Prefixo</span><select defaultValue={prefixId ?? ""} name="prefix"><option value="">Todos</option>{prefixes.data.map((prefix) => <option key={prefix.id} value={prefix.id}>{prefix.prefix}{prefix.name ? ` · ${prefix.name}` : ""}</option>)}</select></label>
        <label className="field"><span className="field__label">Estado</span><select defaultValue={state ?? ""} name="state"><option value="">Todos</option>{stateOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
        <button className="button button--secondary" type="submit"><OperationalIcon name="filter" size={17} />Aplicar</button>
      </form>

      <section className="section-block">
        <div className="section-heading">
          <div><span className="eyebrow">Prefixos</span><h2>Capacidade por bloco</h2></div>
          <span className="section-heading__note">{conflictTotal > 0 ? `${conflictTotal} conflito(s) visível(is)` : "Sem conflito nas alocações carregadas"}</span>
        </div>
        {prefixes.data.length === 0 ? (
          <IpamState title="Nenhum prefixo cadastrado" message="Cadastre o primeiro CIDR deste routing domain. Nenhum bloco de demonstração é criado automaticamente." />
        ) : (
          <div className="prefix-grid">
            {prefixes.data.map((prefix) => (
              <PrefixCard canDelete={canDelete} canUpdate={canUpdate} key={prefix.id} prefix={prefix} routingDomain={routingDomain} siteId={site.id} />
            ))}
          </div>
        )}
      </section>

      <section className="section-block">
        <div className="section-heading"><div><span className="eyebrow">Alocações</span><h2>Endereços persistidos</h2></div><span className="section-heading__note">Estados available são derivados da capacidade, não materializados em milhões de linhas</span></div>
        {addresses.data.length === 0 ? (
          <IpamState title="Nenhuma alocação encontrada" message="O filtro atual não possui reservas, atribuições, observações, conflitos ou exclusões persistidas." />
        ) : (
          <div className="address-list">
            {addresses.data.map((address) => (
              <article className="address-row" key={address.id}>
                <div className="address-row__main"><Icon name="ipam" size={18} /><div><strong>{address.address}</strong><span>{address.dnsName ?? "DNS não informado"}</span></div></div>
                <div><span>Estado</span><strong className="state-badge" data-state={address.state}>{stateLabel(address.state)}</strong></div>
                <div><span>Origem</span><strong>{address.source}</strong></div>
                <div><span>Vínculo</span><strong>{address.deviceId ? "Dispositivo" : address.interfaceId ? "Interface" : "Sem vínculo"}</strong></div>
                <div className="address-row__actions">
                  {canUpdate ? <Link className="icon-action" href={`/ipam/addresses/${address.id}?site=${site.id}&routingDomain=${routingDomain.id}`}><OperationalIcon name="edit" size={16} /><span>Editar</span></Link> : null}
                  {canDelete ? (
                    <form action={deleteAddressAction}>
                      <input name="siteId" type="hidden" value={site.id} /><input name="resourceId" type="hidden" value={address.id} /><input name="expectedVersion" type="hidden" value={address.version} /><input name="returnTo" type="hidden" value={currentHref(site.id, routingDomain.id, params)} />
                      <button className="icon-action icon-action--danger" type="submit"><OperationalIcon name="retire" size={16} /><span>Remover</span></button>
                    </form>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        )}
        <nav className="pagination" aria-label="Paginação de endereços">
          {offset > 0 ? <Link className="button button--secondary" href={pageHref(params, site.id, routingDomain.id, Math.max(0, offset - 100))}>Anterior</Link> : <span />}
          <span>Offset {offset}</span>
          {addresses.data.length === 100 ? <Link className="button button--secondary" href={pageHref(params, site.id, routingDomain.id, offset + 100)}>Próxima</Link> : <span />}
        </nav>
      </section>
    </div>
  );
}

function PrefixCard({ prefix, routingDomain, siteId, canUpdate, canDelete }: { prefix: IpPrefix; routingDomain: RoutingDomain; siteId: string; canUpdate: boolean; canDelete: boolean }) {
  const available = subtractDecimal(prefix.capacity.totalAddresses, prefix.capacity.allocatedAddresses);
  return (
    <article className="prefix-card">
      <div className="prefix-card__head"><span className="prefix-card__icon"><Icon name="ipam" size={20} /></span><div><strong>{prefix.prefix}</strong><span>{prefix.name ?? "Sem nome"}</span></div></div>
      <dl className="prefix-card__stats">
        <div><dt>Alocados</dt><dd>{prefix.capacity.allocatedAddresses}</dd></div>
        <div><dt>Disponíveis</dt><dd title={available}>{compactBigInteger(available)}</dd></div>
        <div><dt>Uso</dt><dd>{formatPercent(prefix.capacity.utilizationPercent)}</dd></div>
      </dl>
      <div className="capacity-bar" aria-label={`Utilização ${formatPercent(prefix.capacity.utilizationPercent)}`}><span style={{ width: `${Math.min(100, Math.max(0, prefix.capacity.utilizationPercent))}%` }} /></div>
      <div className="prefix-card__meta"><span>Gateway: <strong>{prefix.gateway ?? "—"}</strong></span><span>VLAN: <strong>{prefix.vlanId ?? "—"}</strong></span><span>VRF: <strong>{routingDomain.name}</strong></span></div>
      <div className="prefix-card__actions">
        {canUpdate ? <Link className="icon-action" href={`/ipam/prefixes/${prefix.id}?site=${siteId}`}><OperationalIcon name="edit" size={16} /><span>Editar</span></Link> : null}
        {canDelete ? (
          <form action={deletePrefixAction}><input name="siteId" type="hidden" value={siteId} /><input name="resourceId" type="hidden" value={prefix.id} /><input name="expectedVersion" type="hidden" value={prefix.version} /><input name="returnTo" type="hidden" value={`/ipam?site=${siteId}&routingDomain=${routingDomain.id}`} /><button className="icon-action icon-action--danger" type="submit"><OperationalIcon name="retire" size={16} /><span>Remover</span></button></form>
        ) : null}
      </div>
    </article>
  );
}

function IpamState({ title, message, error = false }: { title: string; message: string; error?: boolean }) {
  return <section className={`operational-state${error ? " operational-state--error" : ""}`}><span className="operational-state__icon"><OperationalIcon name={error ? "lock" : "empty"} size={22} /></span><div><span className="eyebrow">Estado real</span><h2>{title}</h2><p>{message}</p></div></section>;
}

function selectSite(sites: SiteContext[], requested?: string) { return sites.find((site) => site.id === requested && site.permissions.includes("ipam.view")) ?? sites.find((site) => site.permissions.includes("ipam.view")); }
function selectRoutingDomain(site: SiteContext, requested?: string) { return site.routingDomains.find((domain) => domain.id === requested) ?? site.defaultRoutingDomain ?? site.routingDomains[0]; }
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }
function asState(value: string | undefined): AddressState | undefined { return stateOptions.some((option) => option.value === value) ? value as AddressState : undefined; }
function stateLabel(value: AddressState) { return value === "available" ? "Disponível" : stateOptions.find((option) => option.value === value)?.label ?? value; }
function nonNegativeInteger(value: string | undefined) { const parsed = Number.parseInt(value ?? "0", 10); return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0; }
function formatPercent(value: number) { return `${new Intl.NumberFormat("pt-BR", { maximumFractionDigits: 2 }).format(value)}%`; }
function subtractDecimal(total: string, allocated: number) { try { return (BigInt(total) - BigInt(allocated)).toString(); } catch { return total; } }
function compactBigInteger(value: string) { try { const number = BigInt(value); if (number < 1_000_000n) return number.toString(); return new Intl.NumberFormat("pt-BR", { notation: "compact", maximumFractionDigits: 2 }).format(Number(number)); } catch { return value; } }
function currentHref(siteId: string, routingDomainId: string, params: Record<string, string | string[] | undefined>) { return pageHref(params, siteId, routingDomainId, nonNegativeInteger(scalar(params.offset))); }
function pageHref(params: Record<string, string | string[] | undefined>, siteId: string, routingDomainId: string, offset: number) { const query = new URLSearchParams({ site: siteId, routingDomain: routingDomainId, offset: String(offset) }); for (const key of ["search", "prefix", "state"] as const) { const value = scalar(params[key]); if (value) query.set(key, value); } return `/ipam?${query.toString()}`; }
