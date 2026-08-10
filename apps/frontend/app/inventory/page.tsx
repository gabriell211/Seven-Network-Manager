import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import type { DeviceLifecycle, DeviceType, SiteContext } from "@/src/generated/api-contract";
import { Icon } from "@/src/components/icon";
import { OperationalIcon, type OperationalIconName } from "@/src/components/operational-icon";
import { getOperationalContext, listDevices } from "@/src/lib/session";

export const metadata: Metadata = { title: "Inventário" };

const lifecycleOptions: ReadonlyArray<{ value: DeviceLifecycle; label: string }> = [
  { value: "discovered", label: "Descoberto" },
  { value: "pending_review", label: "Aguardando revisão" },
  { value: "managed", label: "Gerenciado" },
  { value: "unmanaged", label: "Não gerenciado" },
  { value: "maintenance", label: "Manutenção" },
  { value: "retired", label: "Aposentado" },
  { value: "archived", label: "Arquivado" },
];

const typeOptions: ReadonlyArray<{ value: DeviceType; label: string }> = [
  { value: "switch", label: "Switch" },
  { value: "router", label: "Roteador" },
  { value: "firewall", label: "Firewall" },
  { value: "server", label: "Servidor" },
  { value: "printer", label: "Impressora" },
  { value: "access_point", label: "Access Point" },
  { value: "unknown", label: "Desconhecido" },
];

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function InventoryPage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const context = await getOperationalContext();
  if (!context.ok) {
    if (context.status === 401) redirect("/login");
    return <InventoryError code={context.error.code} message={context.error.message} />;
  }

  const selectedSite = selectSite(context.data.sites, scalar(params.site));
  if (!selectedSite) {
    return (
      <InventoryEmpty
        title="Nenhum site acessível"
        description="A sessão está válida, mas não possui um site autorizado. O backend precisa conceder um role binding antes de qualquer ativo ser exibido."
      />
    );
  }

  const search = scalar(params.search)?.trim() || undefined;
  const lifecycle = asLifecycle(scalar(params.lifecycle));
  const deviceType = asDeviceType(scalar(params.deviceType));
  const offset = nonNegativeInteger(scalar(params.offset));
  const devices = await listDevices(selectedSite.id, {
    search,
    lifecycle,
    deviceType,
    limit: 50,
    offset,
  });

  if (!devices.ok) {
    if (devices.status === 401) redirect("/login");
    return <InventoryError code={devices.error.code} message={devices.error.message} />;
  }

  const canCreate = selectedSite.permissions.includes("devices.create");
  const hasPrevious = offset > 0;
  const hasNext = devices.data.length === 50;

  return (
    <div className="page-stack">
      <section className="page-heading inventory-heading">
        <div>
          <span className="eyebrow">Ativos gerenciados</span>
          <h1>Inventário</h1>
          <p>Dispositivos lidos do PostgreSQL pelo contrato escopado de site. IP não é usado como identidade global.</p>
        </div>
        {canCreate ? (
          <Link className="button button--primary" href={`/inventory/new?site=${selectedSite.id}`}>
            <OperationalIcon name="plus" size={18} />
            Adicionar dispositivo
          </Link>
        ) : null}
      </section>

      <section className="context-bar" aria-label="Contexto operacional">
        <div>
          <span className="eyebrow">Organização</span>
          <strong>{context.data.organization.name}</strong>
        </div>
        <div>
          <span className="eyebrow">Site</span>
          <strong>{selectedSite.name}</strong>
        </div>
        <div>
          <span className="eyebrow">Routing domain</span>
          <strong>{selectedSite.defaultRoutingDomain?.name ?? "Não definido"}</strong>
        </div>
        <div>
          <span className="eyebrow">Resultados carregados</span>
          <strong>{devices.data.length}</strong>
        </div>
      </section>

      <form className="inventory-filters" method="get">
        <label className="field field--search">
          <span className="field__label">Buscar</span>
          <span className="field__control">
            <OperationalIcon name="search" size={18} />
            <input defaultValue={search} name="search" placeholder="IP, MAC, hostname, serial ou identificador" />
          </span>
        </label>
        <label className="field">
          <span className="field__label">Site</span>
          <select defaultValue={selectedSite.id} name="site">
            {context.data.sites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
          </select>
        </label>
        <label className="field">
          <span className="field__label">Lifecycle</span>
          <select defaultValue={lifecycle ?? ""} name="lifecycle">
            <option value="">Todos</option>
            {lifecycleOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </label>
        <label className="field">
          <span className="field__label">Tipo</span>
          <select defaultValue={deviceType ?? ""} name="deviceType">
            <option value="">Todos</option>
            {typeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </label>
        <button className="button button--secondary" type="submit">
          <OperationalIcon name="filter" size={18} />
          Aplicar filtros
        </button>
      </form>

      {devices.data.length === 0 ? (
        <InventoryEmpty
          title="Nenhum dispositivo encontrado"
          description="Não há ativos que correspondam ao site e aos filtros atuais. Nenhum registro de demonstração foi inserido para preencher esta tela."
        />
      ) : (
        <section className="inventory-list" aria-label="Dispositivos">
          {devices.data.map((device) => {
            const icon = deviceTypeIcon(device.deviceType);
            const primaryName = device.displayName ?? device.hostname ?? device.serialNumber ?? "Sem nome declarado";
            return (
              <Link className="device-row" href={`/inventory/${device.id}?site=${selectedSite.id}`} key={device.id}>
                <span className="device-row__icon"><OperationalIcon name={icon} size={21} /></span>
                <div className="device-row__identity">
                  <strong>{primaryName}</strong>
                  <span>{device.hostname ?? "Hostname não informado"}</span>
                </div>
                <div className="device-row__cell">
                  <span>Tipo</span>
                  <strong>{typeLabel(device.deviceType)}</strong>
                </div>
                <div className="device-row__cell">
                  <span>Fabricante / modelo</span>
                  <strong>{[device.vendor, device.model].filter(Boolean).join(" · ") || "Não informado"}</strong>
                </div>
                <div className="device-row__cell">
                  <span>Lifecycle</span>
                  <strong className="state-badge" data-state={device.lifecycle}>{lifecycleLabel(device.lifecycle)}</strong>
                </div>
                <OperationalIcon className="device-row__chevron" name="chevronRight" size={18} />
              </Link>
            );
          })}
        </section>
      )}

      <nav className="pagination" aria-label="Paginação do inventário">
        {hasPrevious ? (
          <Link className="button button--secondary" href={pageHref(params, selectedSite.id, Math.max(0, offset - 50))}>Anterior</Link>
        ) : <span />}
        <span>Offset {offset}</span>
        {hasNext ? (
          <Link className="button button--secondary" href={pageHref(params, selectedSite.id, offset + 50)}>Próxima</Link>
        ) : <span />}
      </nav>
    </div>
  );
}

function InventoryError({ code, message }: { code: string; message: string }) {
  return (
    <section className="operational-state operational-state--error" role="alert">
      <span className="operational-state__icon"><Icon name="warning" size={24} /></span>
      <div><span className="eyebrow">{code}</span><h1>Inventário indisponível</h1><p>{message}</p></div>
    </section>
  );
}

function InventoryEmpty({ title, description }: { title: string; description: string }) {
  return (
    <section className="operational-state">
      <span className="operational-state__icon"><OperationalIcon name="empty" size={24} /></span>
      <div><span className="eyebrow">Estado real</span><h2>{title}</h2><p>{description}</p></div>
    </section>
  );
}

function selectSite(sites: SiteContext[], requested?: string) {
  return sites.find((site) => site.id === requested) ?? sites[0];
}

function scalar(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

function nonNegativeInteger(value: string | undefined) {
  const parsed = Number.parseInt(value ?? "0", 10);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
}

function asLifecycle(value: string | undefined): DeviceLifecycle | undefined {
  return lifecycleOptions.some((option) => option.value === value) ? value as DeviceLifecycle : undefined;
}

function asDeviceType(value: string | undefined): DeviceType | undefined {
  return typeOptions.some((option) => option.value === value) ? value as DeviceType : undefined;
}

function lifecycleLabel(value: DeviceLifecycle) {
  return lifecycleOptions.find((option) => option.value === value)?.label ?? value;
}

function typeLabel(value: DeviceType) {
  return typeOptions.find((option) => option.value === value)?.label ?? value;
}

function deviceTypeIcon(value: DeviceType): OperationalIconName {
  const map: Record<DeviceType, OperationalIconName> = {
    switch: "switch",
    router: "router",
    firewall: "firewall",
    server: "server",
    printer: "printer",
    access_point: "accessPoint",
    unknown: "unknown",
  };
  return map[value];
}

function pageHref(params: Record<string, string | string[] | undefined>, siteId: string, offset: number) {
  const query = new URLSearchParams();
  query.set("site", siteId);
  for (const key of ["search", "lifecycle", "deviceType"] as const) {
    const value = scalar(params[key]);
    if (value) query.set(key, value);
  }
  query.set("offset", String(offset));
  return `/inventory?${query.toString()}`;
}
