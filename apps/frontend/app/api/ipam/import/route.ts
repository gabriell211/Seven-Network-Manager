import { NextResponse } from "next/server";
import * as v from "valibot";

import type { AddressState, NewIpAddress, NewIpPrefix } from "@/src/generated/api-contract";
import {
  createIpamAddress,
  createIpamPrefix,
  getOperationalContext,
  listIpamPrefixes,
} from "@/src/lib/session";

const ScopeSchema = v.object({
  site: v.pipe(v.string(), v.uuid()),
  routingDomain: v.pipe(v.string(), v.uuid()),
});

const writableStates = new Set<AddressState>(["reserved", "assigned", "observed", "conflict", "excluded"]);
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_ROWS = 5_000;

interface ImportRowResult {
  row: number;
  recordType: string;
  status: "imported" | "failed";
  code?: string;
  message?: string;
  resourceId?: string;
}

export async function POST(request: Request) {
  const form = await request.formData();
  const parsedScope = v.safeParse(ScopeSchema, {
    site: text(form.get("site")),
    routingDomain: text(form.get("routingDomain")),
  });
  if (!parsedScope.success) {
    return NextResponse.json({ code: "invalid_import_scope", message: "site and routingDomain must be valid UUIDs" }, { status: 422 });
  }
  const file = form.get("file");
  if (!(file instanceof File) || file.size === 0) {
    return NextResponse.json({ code: "missing_import_file", message: "a non-empty CSV file is required" }, { status: 422 });
  }
  if (file.size > MAX_BYTES) {
    return NextResponse.json({ code: "import_file_too_large", message: `CSV must be at most ${MAX_BYTES} bytes` }, { status: 413 });
  }

  const context = await getOperationalContext();
  if (!context.ok) return NextResponse.json(context.error, { status: context.status });
  const site = context.data.sites.find((candidate) => candidate.id === parsedScope.output.site && candidate.permissions.includes("ipam.create"));
  if (!site || !site.routingDomains.some((domain) => domain.id === parsedScope.output.routingDomain)) {
    return NextResponse.json({ code: "permission_denied", message: "requested import scope is not available to this session" }, { status: 403 });
  }

  const matrix = parseCsv(await file.text());
  if (matrix.length < 2) {
    return NextResponse.json({ code: "empty_import", message: "CSV must contain a header and at least one data row" }, { status: 422 });
  }
  if (matrix.length - 1 > MAX_ROWS) {
    return NextResponse.json({ code: "too_many_import_rows", message: `CSV import is limited to ${MAX_ROWS} rows` }, { status: 413 });
  }
  const headers = matrix[0] ?? [];
  const required = ["recordType"];
  if (required.some((header) => !headers.includes(header))) {
    return NextResponse.json({ code: "invalid_import_header", message: "CSV must include recordType" }, { status: 422 });
  }

  const existing = await listIpamPrefixes(site.id, parsedScope.output.routingDomain);
  if (!existing.ok) return NextResponse.json(existing.error, { status: existing.status });
  const prefixById = new Map(existing.data.map((prefix) => [prefix.id, prefix]));
  const prefixByCidr = new Map(existing.data.map((prefix) => [prefix.prefix, prefix]));
  const rows = matrix.slice(1).map((values, index) => ({ number: index + 2, data: rowObject(headers, values) }));
  const report: ImportRowResult[] = [];

  for (const row of rows.filter((item) => item.data.recordType === "prefix")) {
    const scopeError = checkRowScope(row.data.routingDomainId, parsedScope.output.routingDomain);
    if (scopeError) {
      report.push(failed(row.number, "prefix", "scope_mismatch", scopeError));
      continue;
    }
    if (!row.data.prefix) {
      report.push(failed(row.number, "prefix", "missing_prefix", "prefix is required"));
      continue;
    }
    const vlan = optionalInteger(row.data.vlanId);
    if (vlan === "invalid") {
      report.push(failed(row.number, "prefix", "invalid_vlan", "vlanId must be an integer"));
      continue;
    }
    const input: NewIpPrefix = {
      routingDomainId: parsedScope.output.routingDomain,
      prefix: row.data.prefix,
      name: nullable(row.data.name),
      gateway: nullable(row.data.gateway),
      vlanId: vlan,
      purpose: nullable(row.data.purpose),
      description: nullable(row.data.description),
    };
    const result = await createIpamPrefix(site.id, input);
    if (!result.ok) {
      report.push(failed(row.number, "prefix", result.error.code, result.error.message));
      continue;
    }
    prefixById.set(result.data.id, result.data);
    prefixByCidr.set(result.data.prefix, result.data);
    report.push({ row: row.number, recordType: "prefix", status: "imported", resourceId: result.data.id });
  }

  for (const row of rows.filter((item) => item.data.recordType === "address")) {
    const scopeError = checkRowScope(row.data.routingDomainId, parsedScope.output.routingDomain);
    if (scopeError) {
      report.push(failed(row.number, "address", "scope_mismatch", scopeError));
      continue;
    }
    if (!row.data.address) {
      report.push(failed(row.number, "address", "missing_address", "address is required"));
      continue;
    }
    const state = row.data.state as AddressState | undefined;
    if (!state || !writableStates.has(state)) {
      report.push(failed(row.number, "address", "invalid_state", "state must be reserved, assigned, observed, conflict or excluded"));
      continue;
    }
    const prefix = (row.data.prefixId ? prefixById.get(row.data.prefixId) : undefined) ?? (row.data.prefix ? prefixByCidr.get(row.data.prefix) : undefined);
    if (!prefix) {
      report.push(failed(row.number, "address", "prefix_not_found", "prefixId or prefix must resolve to an existing/imported prefix in this routing domain"));
      continue;
    }
    const input: NewIpAddress = {
      routingDomainId: parsedScope.output.routingDomain,
      prefixId: prefix.id,
      address: row.data.address,
      state,
      source: row.data.source || "import",
      dnsName: nullable(row.data.dnsName),
      deviceId: nullable(row.data.deviceId),
      interfaceId: nullable(row.data.interfaceId),
      description: nullable(row.data.description),
    };
    const result = await createIpamAddress(site.id, input);
    if (!result.ok) {
      report.push(failed(row.number, "address", result.error.code, result.error.message));
      continue;
    }
    report.push({ row: row.number, recordType: "address", status: "imported", resourceId: result.data.id });
  }

  for (const row of rows.filter((item) => item.data.recordType !== "prefix" && item.data.recordType !== "address")) {
    report.push(failed(row.number, row.data.recordType || "unknown", "invalid_record_type", "recordType must be prefix or address"));
  }

  const imported = report.filter((item) => item.status === "imported").length;
  const failedCount = report.length - imported;
  return NextResponse.json({
    received: rows.length,
    imported,
    failed: failedCount,
    rows: report,
  }, { status: failedCount > 0 ? 207 : 200 });
}

function parseCsv(input: string) {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    if (quoted) {
      if (char === '"' && input[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
      continue;
    }
    if (char === '"') quoted = true;
    else if (char === ",") { row.push(field); field = ""; }
    else if (char === "\n") { row.push(field.replace(/\r$/, "")); rows.push(row); row = []; field = ""; }
    else field += char;
  }
  if (field.length > 0 || row.length > 0) { row.push(field.replace(/\r$/, "")); rows.push(row); }
  return rows.filter((item) => item.some((value) => value.trim() !== ""));
}

function rowObject(headers: string[], values: string[]) {
  return Object.fromEntries(headers.map((header, index) => [header.trim(), (values[index] ?? "").trim()])) as Record<string, string>;
}

function failed(row: number, recordType: string, code: string, message: string): ImportRowResult {
  return { row, recordType, status: "failed", code, message };
}

function checkRowScope(value: string | undefined, expected: string) {
  return value && value !== expected ? "row routingDomainId differs from the explicitly selected import scope" : null;
}

function optionalInteger(value: string | undefined): number | null | "invalid" {
  if (!value) return null;
  if (!/^\d+$/.test(value)) return "invalid";
  return Number(value);
}

function nullable(value: string | undefined) { return value || null; }
function text(value: FormDataEntryValue | null) { return typeof value === "string" ? value : ""; }
