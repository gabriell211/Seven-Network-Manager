"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import * as v from "valibot";

import type { AddressState, NewIpAddress, NewIpPrefix, UpdateIpAddress, UpdateIpPrefix } from "@/src/generated/api-contract";
import {
  createIpamAddress,
  createIpamPrefix,
  deleteIpamAddress,
  deleteIpamPrefix,
  updateIpamAddress,
  updateIpamPrefix,
} from "@/src/lib/session";

const writableStates = ["reserved", "assigned", "observed", "conflict", "excluded"] as const;

const PrefixSchema = v.object({
  siteId: v.pipe(v.string(), v.uuid()),
  routingDomainId: v.pipe(v.string(), v.uuid()),
  prefix: v.pipe(v.string(), v.trim(), v.minLength(3), v.maxLength(64)),
  name: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  gateway: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(64))),
  vlanId: v.optional(v.pipe(v.string(), v.regex(/^\d{1,4}$/))),
  purpose: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  description: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(4000))),
});

const PrefixUpdateSchema = v.object({
  siteId: v.pipe(v.string(), v.uuid()),
  prefixId: v.pipe(v.string(), v.uuid()),
  expectedVersion: v.pipe(v.string(), v.regex(/^\d+$/)),
  routingDomainId: v.pipe(v.string(), v.uuid()),
  prefix: v.pipe(v.string(), v.trim(), v.minLength(3), v.maxLength(64)),
  name: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  gateway: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(64))),
  vlanId: v.optional(v.pipe(v.string(), v.regex(/^\d{1,4}$/))),
  purpose: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  description: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(4000))),
});

const AddressSchema = v.object({
  siteId: v.pipe(v.string(), v.uuid()),
  routingDomainId: v.pipe(v.string(), v.uuid()),
  prefixId: v.pipe(v.string(), v.uuid()),
  address: v.pipe(v.string(), v.trim(), v.minLength(2), v.maxLength(64)),
  state: v.picklist(writableStates),
  source: v.pipe(v.string(), v.trim(), v.minLength(1), v.maxLength(120)),
  dnsName: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  deviceId: v.optional(v.pipe(v.string(), v.uuid())),
  interfaceId: v.optional(v.pipe(v.string(), v.uuid())),
  description: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(4000))),
});

const AddressUpdateSchema = v.object({
  siteId: v.pipe(v.string(), v.uuid()),
  addressId: v.pipe(v.string(), v.uuid()),
  expectedVersion: v.pipe(v.string(), v.regex(/^\d+$/)),
  state: v.picklist(writableStates),
  source: v.pipe(v.string(), v.trim(), v.minLength(1), v.maxLength(120)),
  dnsName: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  deviceId: v.optional(v.pipe(v.string(), v.uuid())),
  interfaceId: v.optional(v.pipe(v.string(), v.uuid())),
  description: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(4000))),
});

const DeleteSchema = v.object({
  siteId: v.pipe(v.string(), v.uuid()),
  resourceId: v.pipe(v.string(), v.uuid()),
  expectedVersion: v.pipe(v.string(), v.regex(/^\d+$/)),
  returnTo: v.pipe(v.string(), v.startsWith("/ipam"), v.maxLength(1000)),
});

export async function createPrefixAction(formData: FormData) {
  const parsed = v.safeParse(PrefixSchema, prefixInput(formData));
  const siteId = field(formData, "siteId");
  if (!parsed.success) redirectError("/ipam/new-prefix", siteId, "invalid_prefix_input");

  const input: NewIpPrefix = {
    routingDomainId: parsed.output.routingDomainId,
    prefix: parsed.output.prefix,
    ...nullableText("name", parsed.output.name),
    ...nullableText("gateway", parsed.output.gateway),
    ...(parsed.output.vlanId ? { vlanId: Number(parsed.output.vlanId) } : {}),
    ...nullableText("purpose", parsed.output.purpose),
    ...nullableText("description", parsed.output.description),
  };
  const result = await createIpamPrefix(parsed.output.siteId, input);
  if (!result.ok) redirectError("/ipam/new-prefix", parsed.output.siteId, result.error.code);

  revalidatePath("/ipam");
  redirect(`/ipam?site=${parsed.output.siteId}&routingDomain=${parsed.output.routingDomainId}&saved=prefix`);
}

export async function updatePrefixAction(formData: FormData) {
  const parsed = v.safeParse(PrefixUpdateSchema, {
    ...prefixInput(formData),
    prefixId: field(formData, "prefixId"),
    expectedVersion: field(formData, "expectedVersion"),
  });
  const siteId = field(formData, "siteId");
  const prefixId = field(formData, "prefixId");
  if (!parsed.success) redirectResourceError("prefixes", prefixId, siteId, "invalid_prefix_input");

  const input: UpdateIpPrefix = {
    expectedVersion: Number(parsed.output.expectedVersion),
    routingDomainId: parsed.output.routingDomainId,
    prefix: parsed.output.prefix,
    name: parsed.output.name || null,
    gateway: parsed.output.gateway || null,
    vlanId: parsed.output.vlanId ? Number(parsed.output.vlanId) : null,
    purpose: parsed.output.purpose || null,
    description: parsed.output.description || null,
  };
  const result = await updateIpamPrefix(parsed.output.siteId, parsed.output.prefixId, input);
  if (!result.ok) redirectResourceError("prefixes", parsed.output.prefixId, parsed.output.siteId, result.error.code);

  revalidatePath("/ipam");
  redirect(`/ipam/prefixes/${parsed.output.prefixId}?site=${parsed.output.siteId}&saved=1`);
}

export async function createAddressAction(formData: FormData) {
  const parsed = v.safeParse(AddressSchema, addressInput(formData));
  const siteId = field(formData, "siteId");
  if (!parsed.success) redirectError("/ipam/new-address", siteId, "invalid_address_input");

  const input: NewIpAddress = {
    routingDomainId: parsed.output.routingDomainId,
    prefixId: parsed.output.prefixId,
    address: parsed.output.address,
    state: parsed.output.state as AddressState,
    source: parsed.output.source,
    dnsName: parsed.output.dnsName || null,
    deviceId: parsed.output.deviceId || null,
    interfaceId: parsed.output.interfaceId || null,
    description: parsed.output.description || null,
  };
  const result = await createIpamAddress(parsed.output.siteId, input);
  if (!result.ok) redirectError("/ipam/new-address", parsed.output.siteId, result.error.code);

  revalidatePath("/ipam");
  redirect(`/ipam?site=${parsed.output.siteId}&routingDomain=${parsed.output.routingDomainId}&saved=address`);
}

export async function updateAddressAction(formData: FormData) {
  const parsed = v.safeParse(AddressUpdateSchema, {
    ...addressInput(formData),
    addressId: field(formData, "addressId"),
    expectedVersion: field(formData, "expectedVersion"),
  });
  const siteId = field(formData, "siteId");
  const addressId = field(formData, "addressId");
  if (!parsed.success) redirectResourceError("addresses", addressId, siteId, "invalid_address_input");

  const input: UpdateIpAddress = {
    expectedVersion: Number(parsed.output.expectedVersion),
    state: parsed.output.state as AddressState,
    source: parsed.output.source,
    dnsName: parsed.output.dnsName || null,
    deviceId: parsed.output.deviceId || null,
    interfaceId: parsed.output.interfaceId || null,
    description: parsed.output.description || null,
  };
  const result = await updateIpamAddress(parsed.output.siteId, parsed.output.addressId, input);
  if (!result.ok) redirectResourceError("addresses", parsed.output.addressId, parsed.output.siteId, result.error.code);

  revalidatePath("/ipam");
  redirect(`/ipam/addresses/${parsed.output.addressId}?site=${parsed.output.siteId}&saved=1`);
}

export async function deletePrefixAction(formData: FormData) {
  const parsed = v.safeParse(DeleteSchema, deleteInput(formData));
  if (!parsed.success) redirect("/ipam?error=invalid_delete_request");
  const result = await deleteIpamPrefix(parsed.output.siteId, parsed.output.resourceId, {
    expectedVersion: Number(parsed.output.expectedVersion),
  });
  if (!result.ok) redirect(`${parsed.output.returnTo}${parsed.output.returnTo.includes("?") ? "&" : "?"}error=${encodeURIComponent(result.error.code)}`);
  revalidatePath("/ipam");
  redirect(`${parsed.output.returnTo}${parsed.output.returnTo.includes("?") ? "&" : "?"}deleted=prefix`);
}

export async function deleteAddressAction(formData: FormData) {
  const parsed = v.safeParse(DeleteSchema, deleteInput(formData));
  if (!parsed.success) redirect("/ipam?error=invalid_delete_request");
  const result = await deleteIpamAddress(parsed.output.siteId, parsed.output.resourceId, {
    expectedVersion: Number(parsed.output.expectedVersion),
  });
  if (!result.ok) redirect(`${parsed.output.returnTo}${parsed.output.returnTo.includes("?") ? "&" : "?"}error=${encodeURIComponent(result.error.code)}`);
  revalidatePath("/ipam");
  redirect(`${parsed.output.returnTo}${parsed.output.returnTo.includes("?") ? "&" : "?"}deleted=address`);
}

function prefixInput(formData: FormData) {
  return {
    siteId: field(formData, "siteId"),
    routingDomainId: field(formData, "routingDomainId"),
    prefix: field(formData, "prefix"),
    name: optionalField(formData, "name"),
    gateway: optionalField(formData, "gateway"),
    vlanId: optionalField(formData, "vlanId"),
    purpose: optionalField(formData, "purpose"),
    description: optionalField(formData, "description"),
  };
}

function addressInput(formData: FormData) {
  return {
    siteId: field(formData, "siteId"),
    routingDomainId: field(formData, "routingDomainId"),
    prefixId: field(formData, "prefixId"),
    address: field(formData, "address"),
    state: field(formData, "state"),
    source: field(formData, "source"),
    dnsName: optionalField(formData, "dnsName"),
    deviceId: optionalField(formData, "deviceId"),
    interfaceId: optionalField(formData, "interfaceId"),
    description: optionalField(formData, "description"),
  };
}

function deleteInput(formData: FormData) {
  return {
    siteId: field(formData, "siteId"),
    resourceId: field(formData, "resourceId"),
    expectedVersion: field(formData, "expectedVersion"),
    returnTo: field(formData, "returnTo"),
  };
}

function field(formData: FormData, name: string) {
  const value = formData.get(name);
  return typeof value === "string" ? value : "";
}

function optionalField(formData: FormData, name: string) {
  const value = field(formData, name).trim();
  return value || undefined;
}

function nullableText<K extends string>(key: K, value: string | undefined) {
  return value ? ({ [key]: value } as Record<K, string>) : {};
}

function redirectError(path: string, siteId: string, code: string): never {
  const query = new URLSearchParams({ site: siteId, error: code });
  redirect(`${path}?${query.toString()}`);
}

function redirectResourceError(kind: "prefixes" | "addresses", id: string, siteId: string, code: string): never {
  const query = new URLSearchParams({ site: siteId, error: code });
  redirect(`/ipam/${kind}/${id}?${query.toString()}`);
}
