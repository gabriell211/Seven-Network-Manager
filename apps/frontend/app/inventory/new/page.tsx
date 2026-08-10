import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { OperationalIcon } from "@/src/components/operational-icon";
import { getOperationalContext } from "@/src/lib/session";

import { createDeviceAction } from "../actions";

export const metadata: Metadata = { title: "Adicionar dispositivo" };

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function NewDevicePage({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const context = await getOperationalContext();
  if (!context.ok) {
    if (context.status === 401) redirect("/login");
    return <FormState title="Contexto indisponível" message={context.error.message} />;
  }

  const requestedSite = scalar(params.site);
  const site = context.data.sites.find((candidate) => candidate.id === requestedSite) ?? context.data.sites[0];
  if (!site) return <FormState title="Nenhum site acessível" message="Não existe site autorizado para receber o dispositivo." />;
  if (!site.permissions.includes("devices.create")) {
    return <FormState title="Permissão insuficiente" message="Sua sessão não possui devices.create neste site." />;
  }

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div>
          <span className="eyebrow">Onboarding manual</span>
          <h1>Adicionar dispositivo</h1>
          <p>O ativo será criado no site <strong>{site.name}</strong>. Quando aprovação estiver habilitada, ele entra em pending_review e não pode receber mutations antes do onboarding.</p>
        </div>
        <Link className="button button--secondary" href={`/inventory?site=${site.id}`}>Voltar ao inventário</Link>
      </section>

      {scalar(params.error) ? (
        <div className="form-error" role="alert">Falha: {scalar(params.error)}</div>
      ) : null}

      <form action={createDeviceAction} className="device-form">
        <input name="siteId" type="hidden" value={site.id} />

        <section className="form-section">
          <div className="form-section__heading"><OperationalIcon name="monitor" size={20} /><div><h2>Identidade do ativo</h2><p>Informe dados declarados; observações futuras permanecem separadas.</p></div></div>
          <div className="form-grid">
            <label className="field"><span className="field__label">Nome de exibição</span><input name="displayName" /></label>
            <label className="field"><span className="field__label">Tipo</span><select defaultValue="unknown" name="deviceType"><option value="unknown">Desconhecido</option><option value="switch">Switch</option><option value="router">Roteador</option><option value="firewall">Firewall</option><option value="server">Servidor</option><option value="printer">Impressora</option><option value="access_point">Access Point</option></select></label>
            <label className="field"><span className="field__label">Fabricante</span><input name="vendor" /></label>
            <label className="field"><span className="field__label">Modelo</span><input name="model" /></label>
          </div>
        </section>

        <section className="form-section">
          <div className="form-section__heading"><OperationalIcon name="serial" size={20} /><div><h2>Identificadores</h2><p>Informe ao menos um. Serial e MAC são identidades fortes; hostname e asset tag são evidências mais fracas.</p></div></div>
          <div className="form-grid">
            <label className="field"><span className="field__label">Serial</span><input name="serial" /></label>
            <label className="field"><span className="field__label">MAC</span><input autoCapitalize="characters" name="mac" placeholder="AA:BB:CC:00:11:22" /></label>
            <label className="field"><span className="field__label">Hostname</span><input name="hostname" /></label>
            <label className="field"><span className="field__label">Asset tag</span><input name="assetTag" /></label>
          </div>
        </section>

        <section className="form-section">
          <div className="form-section__heading"><OperationalIcon name="owner" size={20} /><div><h2>Contexto operacional</h2><p>Campos administrativos não são substituídos por discovery posterior.</p></div></div>
          <div className="form-grid">
            <label className="field"><span className="field__label">Responsável operacional</span><input name="operationalOwner" /></label>
            <label className="field field--wide"><span className="field__label">Descrição</span><textarea name="description" rows={4} /></label>
          </div>
        </section>

        <div className="form-actions">
          <Link className="button button--secondary" href={`/inventory?site=${site.id}`}>Cancelar</Link>
          <button className="button button--primary" type="submit"><OperationalIcon name="plus" size={18} />Criar dispositivo</button>
        </div>
      </form>
    </div>
  );
}

function FormState({ title, message }: { title: string; message: string }) {
  return <section className="operational-state operational-state--error"><OperationalIcon name="lock" size={24} /><div><h1>{title}</h1><p>{message}</p></div></section>;
}

function scalar(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}
