import { NextResponse } from "next/server";
import * as v from "valibot";

import { getOperationalContext, listIpamAddresses, listIpamPrefixes } from "@/src/lib/session";

const QuerySchema = v.object({
  site: v.pipe(v.string(), v.uuid()),
  routingDomain: v.pipe(v.string(), v.uuid()),
});

export async function GET(request: Request) {
  const url = new URL(request.url);
  const parsed = v.safeParse(QuerySchema, {
    site: url.searchParams.get("site") ?? "",
    routingDomain: url.searchParams.get("routingDomain") ?? "",
  });
  if (!parsed.success) {
    return NextResponse.json({ code: "invalid_export_scope", message: "site and routingDomain must be valid UUIDs" }, { status: 422 });
  }

  const context = await getOperationalContext();
  if (!context.ok) {
    return NextResponse.json(context.error, { status: context.status });
  }
  const site = context.data.sites.find((candidate) => candidate.id === parsed.output.site && candidate.permissions.includes("ipam.view"));
  if (!site || !site.routingDomains.some((domain) => domain.id === parsed.output.routingDomain)) {
    return NextResponse.json({ code: "permission_denied", message: "requested IPAM scope is not available to this session" }, { status: 403 });
  }

  const prefixes = await listIpamPrefixes(site.id, parsed.output.routingDomain);
  if (!prefixes.ok) return NextResponse.json(prefixes.error, { status: prefixes.status });

  const addressPages = [];
  for (let offset = 0; ; offset += 200) {
    const page = await listIpamAddresses(site.id, {
      routingDomainId: parsed.output.routingDomain,
      limit: 200,
      offset,
    });
    if (!page.ok) return NextResponse.json(page.error, { status: page.status });
    addressPages.push(...page.data);
    if (page.data.length < 200) break;
    if (offset >= 199_800) {
      return NextResponse.json({ code: "export_limit_exceeded", message: "export exceeds the supported 200000 allocation limit" }, { status: 413 });
    }
  }

  const rows: string[][] = [[
    "recordType", "id", "routingDomainId", "prefixId", "prefix", "address", "state", "name", "gateway", "vlanId", "purpose", "dnsName", "source", "deviceId", "interfaceId", "description", "version",
  ]];
  for (const prefix of prefixes.data) {
    rows.push([
      "prefix", prefix.id, prefix.routingDomainId, "", prefix.prefix, "", "", prefix.name ?? "", prefix.gateway ?? "", prefix.vlanId?.toString() ?? "", prefix.purpose ?? "", "", "", "", "", prefix.description ?? "", prefix.version.toString(),
    ]);
  }
  for (const address of addressPages) {
    rows.push([
      "address", address.id, address.routingDomainId, address.prefixId ?? "", "", address.address, address.state, "", "", "", "", address.dnsName ?? "", address.source, address.deviceId ?? "", address.interfaceId ?? "", address.description ?? "", address.version.toString(),
    ]);
  }

  const body = rows.map((row) => row.map(csv).join(",")).join("\r\n") + "\r\n";
  const domain = site.routingDomains.find((item) => item.id === parsed.output.routingDomain);
  const filename = sanitize(`snm-ipam-${site.slug}-${domain?.name ?? parsed.output.routingDomain}.csv`);
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": `attachment; filename="${filename}"`,
      "cache-control": "no-store",
    },
  });
}

function csv(value: string) {
  if (!/[",\r\n]/.test(value)) return value;
  return `"${value.replaceAll('"', '""')}"`;
}

function sanitize(value: string) {
  return value.normalize("NFKD").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/-+/g, "-");
}
