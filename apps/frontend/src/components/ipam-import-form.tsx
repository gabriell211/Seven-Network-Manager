"use client";

import { useState } from "react";

import { OperationalIcon } from "./operational-icon";

interface ImportRowResult {
  row: number;
  recordType: string;
  status: "imported" | "failed";
  code?: string;
  message?: string;
  resourceId?: string;
}

interface ImportReport {
  received: number;
  imported: number;
  failed: number;
  rows: ImportRowResult[];
}

export function IpamImportForm({ siteId, routingDomainId }: { siteId: string; routingDomainId: string }) {
  const [pending, setPending] = useState(false);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setReport(null);
    const body = new FormData(event.currentTarget);
    body.set("site", siteId);
    body.set("routingDomain", routingDomainId);
    try {
      const response = await fetch("/api/ipam/import", { method: "POST", body });
      const payload = (await response.json()) as ImportReport | { message?: string };
      if (!response.ok && response.status !== 207) {
        setError("message" in payload && payload.message ? payload.message : "Falha ao importar o arquivo.");
        return;
      }
      setReport(payload as ImportReport);
    } catch {
      setError("Não foi possível alcançar o control plane para importar o arquivo.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="import-panel">
      <form className="import-form" onSubmit={submit}>
        <label className="field">
          <span className="field__label">Arquivo CSV</span>
          <input accept=".csv,text/csv" name="file" required type="file" />
        </label>
        <button className="button button--primary" disabled={pending} type="submit">
          <OperationalIcon name="plus" size={17} />
          {pending ? "Validando e importando…" : "Importar e validar"}
        </button>
      </form>
      {error ? <div className="form-error" role="alert">{error}</div> : null}
      {report ? (
        <div className="import-report" role="status">
          <div className="context-bar">
            <div><span className="eyebrow">Recebidas</span><strong>{report.received}</strong></div>
            <div><span className="eyebrow">Importadas</span><strong>{report.imported}</strong></div>
            <div><span className="eyebrow">Falharam</span><strong>{report.failed}</strong></div>
            <div><span className="eyebrow">Resultado</span><strong>{report.failed === 0 ? "Concluído" : "Parcial"}</strong></div>
          </div>
          {report.rows.some((row) => row.status === "failed") ? (
            <div className="import-errors">
              {report.rows.filter((row) => row.status === "failed").map((row) => (
                <div key={`${row.row}:${row.recordType}`}>
                  <strong>Linha {row.row} · {row.recordType}</strong>
                  <span>{row.code}: {row.message}</span>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
