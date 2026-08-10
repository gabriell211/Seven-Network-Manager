import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import type { DeviceLifecycle, DeviceType, SiteContext } from "@/src/generated/api-contract";
import { OperationalIcon, type OperationalIconName } from "@/src/components/operational-icon";
import { getDevice, getOperationalContext } from "@/src/lib/session";

import { transitionLifecycleAction, updateDeviceAction } from "../actions";

export const metadata: Metadata = { title: "Detalhe do dispositivo" };

type PageParams = Promise<{ deviceId: string }>;
type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function DeviceDetailPage({ params, searchParams }: { params: PageParams; searchParams: SearchParams }) {
  const [{ deviceId }, query] = await Promise.all([params, searchParams]);
  const context = await getOperationalContext();
  if (!context.ok) {
    if (context.status === 401) redirect("/login");
    return <DetailState title="Contexto indisponível" message={context.error.message} />;
  }

  const site = selectSite(context.data.sites, scalar(query.site));
  if (!site) return <DetailState title="Nenhum site acessível" message="A sessão não possui um site autorizado." />;

  const result = await getDevice(site.id, deviceId);
  if (!result.ok) {
    if (result.status === 401) redirect("/login");
    if (result.status === 404) notFound();
    return <DetailState title="Dispositivo indisponível" message={result.error.message} />;
  }

  const device = result.data;
  const canUpdate = site.permissions.includes("devices.update") && ["managed", "maintenance"].includes(device.lifecycle);
  const transitions = lifecycleTransitions(device.lifecycle).filter((next) => site.permissions.includes(permissionForTransition(next)));

  return (
    <div className="page-stack">
      <section className="page-heading inventory-heading">
        <div>
          <span className="eyebrow">Dispositivo · {site.name}</span>
          <h1>{device.displayName ?? device.hostname ?? device.serialNumber ?? "Sem nome declarado"}</h1>
          <p>ID estável: <code>{device.id}</code></p>
        </div>
        <Link className="button button--secondary" href={`/inventory?site=${site.id}`}>Voltar ao inventário</Link>
      </section>

      {scalar(query.saved) === "1" ? <div className="form-success" role="status">Alteração confirmada pelo control plane.</div> : null}
      {scalar(query.error) ? <div className="form-error" role="alert">Falha: {scalar(query.error)}</div> : null}

      <section className="device-overview">
        <OverviewItem icon={deviceIcon(device.deviceType)} label="Tipo" value={typeLabel(device.deviceType)} />
        <OverviewItem icon="serial" label="Serial" value={device.serialNumber ?? "Não informado"} />
        <OverviewItem icon="hostname" label="Hostname" value={device.hostname ?? "Não informado"} />
        <OverviewItem icon="vendor" label="Fabricante" value={device.vendor ?? "Não informado"} />
        <OverviewItem icon="clock" label="Última alteração" value={formatDate(device.lastChangedAt)} />
        <OverviewItem icon="owner" label="Responsável" value={device.operationalOwner ?? "Não informado"} />
      </section>

      <section className="section-block">
        <div className="section-heading"><div><span className="eyebrow">Lifecycle</span><h2>Estado administrativo</h2></div><strong className="state-badge" data-state={device.lifecycle}>{lifecycleLabel(device.lifecycle)}</strong></div>
        <p className="section-copy">O estado controla se mutations normais são permitidas. Discovery nunca promove um host diretamente para gerenciado.</p>
        {transitions.length > 0 ? (
          <div className="lifecycle-actions">
            {transitions.map((next) => (
              <form action={transitionLifecycleAction} className="lifecycle-action" key={next}>
                <input name="siteId" type="hidden" value={site.id} />
                <input name="deviceId" type="hidden" value={device.id} />
                <input name="expectedVersion" type="hidden" value={device.version} />
                <input name="next" type="hidden" value={next} />
                <div><strong>{transitionLabel(next)}</strong><span>{transitionDescription(next)}</span></div>
                {next === "retired" || next === "archived" ? <input aria-label="Motivo" name="reason" placeholder="Motivo obrigatório" required /> : null}
                <button className="button button--secondary" type="submit"><OperationalIcon name={transitionIcon(next)} size={17} />Aplicar</button>
              </form>
            ))}
          </div>
        ) : <p className="muted-note">Não há transição autorizada disponível para este estado e escopo.</p>}
      </section>

      <section className="section-block">
        <div className="section-heading"><div><span className="eyebrow">Dados declarados</span><h2>Metadados operacionais</h2></div>{canUpdate ? <span className="permission-chip">devices.update</span> : <span className="permission-chip permission-chip--locked">Somente leitura</span>}</div>
        {canUpdate ? (
          <form action={updateDeviceAction} className="device-form device-form--embedded">
            <input name="siteId" type="hidden" value={site.id} />
            <input name="deviceId" type="hidden" value={device.id} />
            <input name="expectedVersion" type="hidden" value={device.version} />
            <div className="form-grid">
              <label className="field"><span className="field__label">Nome de exibição</span><input defaultValue={device.displayName ?? ""} name="displayName" /></label>
              <label className="field"><span className="field__label">Tipo</span><select defaultValue={device.deviceType} name="deviceType"><option value="unknown">Desconhecido</option><option value="switch">Switch</option><option value="router">Roteador</option><option value="firewall">Firewall</option><option value="server">Servidor</option><option value="printer">Impressora</option><option value="access_point">Access Point</option></select></label>
              <label className="field"><span className="field__label">Hostname</span><input defaultValue={device.hostname ?? ""} name="hostname" /></label>
              <label className="field"><span className="field__label">Fabricante</span><input defaultValue={device.vendor ?? ""} name="vendor" /></label>
              <label className="field"><span className="field__label">Modelo</span><input defaultValue={device.model ?? ""} name="model" /></label>
              <label className="field"><span className="field__label">OS</span><input defaultValue={device.osName ?? ""} name="osName" /></label>
              <label className="field"><span className="field__label">Versão do OS</span><input defaultValue={device.osVersion ?? ""} name="osVersion" /></label>
              <label className="field"><span className="field__label">Firmware</span><input defaultValue={device.firmwareVersion ?? ""} name="firmwareVersion" /></label>
              <label className="field"><span className="field__label">Responsável operacional</span><input defaultValue={device.operationalOwner ?? ""} name="operationalOwner" /></label>
              <label className="field field--wide"><span className="field__label">Descrição</span><textarea defaultValue={device.description ?? ""} name="description" rows={4} /></label>
            </div>
            <div className="form-actions"><button className="button button--primary" type="submit"><OperationalIcon name="edit" size={17} />Salvar metadados</button></div>
          </form>
        ) : (
          <div className="read-only-grid">
            <ReadOnly label="Modelo" value={device.model} />
            <ReadOnly label="OS" value={[device.osName, device.osVersion].filter(Boolean).join(" ") || null} />
            <ReadOnly label="Firmware" value={device.firmwareVersion} />
            <ReadOnly label="Descrição" value={device.description} />
          </div>
        )}
      </section>

      <section className="section-block">
        <div className="section-heading"><div><span className="eyebrow">Contrato atual</span><h2>Dados não fabricados</h2></div></div>
        <p className="section-copy">Endereços IP, interfaces, tags e credential associations não são exibidos aqui até o contrato REST expor essas relações de forma escopada. A interface não preenche esses campos com placeholders operacionais.</p>
      </section>
    </div>
  );
}

function OverviewItem({ icon, label, value }: { icon: OperationalIconName; label: string; value: string }) {
  return <div className="overview-item"><OperationalIcon name={icon} size={19} /><div><span>{label}</span><strong>{value}</strong></div></div>;
}

function ReadOnly({ label, value }: { label: string; value: string | null | undefined }) {
  return <div><span>{label}</span><strong>{value ?? "Não informado"}</strong></div>;
}

function DetailState({ title, message }: { title: string; message: string }) {
  return <section className="operational-state operational-state--error"><OperationalIcon name="lock" size={24} /><div><h1>{title}</h1><p>{message}</p></div></section>;
}

function selectSite(sites: SiteContext[], requested?: string) { return sites.find((site) => site.id === requested) ?? sites[0]; }
function scalar(value: string | string[] | undefined) { return Array.isArray(value) ? value[0] : value; }
function formatDate(value: string) { return new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "medium", timeZone: "America/Sao_Paulo" }).format(new Date(value)); }
function typeLabel(value: DeviceType) { return ({ switch: "Switch", router: "Roteador", firewall: "Firewall", server: "Servidor", printer: "Impressora", access_point: "Access Point", unknown: "Desconhecido" } as const)[value]; }
function lifecycleLabel(value: DeviceLifecycle) { return ({ discovered: "Descoberto", pending_review: "Aguardando revisão", managed: "Gerenciado", unmanaged: "Não gerenciado", maintenance: "Manutenção", retired: "Aposentado", archived: "Arquivado" } as const)[value]; }
function deviceIcon(value: DeviceType): OperationalIconName { return ({ switch: "switch", router: "router", firewall: "firewall", server: "server", printer: "printer", access_point: "accessPoint", unknown: "unknown" } as const)[value]; }
function permissionForTransition(next: DeviceLifecycle) { return next === "managed" ? "devices.approve" : next === "retired" || next === "archived" ? "devices.delete" : "devices.update"; }
function transitionIcon(next: DeviceLifecycle): OperationalIconName { return next === "managed" ? "approve" : next === "retired" ? "retire" : next === "archived" ? "archive" : "edit"; }
function transitionLabel(next: DeviceLifecycle) { return `Mover para ${lifecycleLabel(next)}`; }
function transitionDescription(next: DeviceLifecycle) { return next === "managed" ? "Aprova o onboarding e libera operações permitidas." : next === "retired" ? "Retira o ativo da operação normal preservando histórico." : next === "archived" ? "Arquiva o recurso conforme lifecycle e retenção." : "Aplica a transição prevista pelo domínio de lifecycle."; }
function lifecycleTransitions(current: DeviceLifecycle): DeviceLifecycle[] {
  const transitions: Record<DeviceLifecycle, DeviceLifecycle[]> = {
    discovered: ["pending_review", "unmanaged", "archived"],
    pending_review: ["managed", "unmanaged", "archived"],
    managed: ["maintenance", "unmanaged", "retired"],
    unmanaged: ["pending_review", "managed", "retired", "archived"],
    maintenance: ["managed", "retired"],
    retired: ["pending_review", "archived"],
    archived: [],
  };
  return transitions[current];
}
