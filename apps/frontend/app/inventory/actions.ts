"use server";

import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import * as v from "valibot";

import type {
  DeviceIdentifierInput,
  DeviceLifecycle,
  DeviceType,
  NewDevice,
  UpdateDeviceRequest,
} from "@/src/generated/api-contract";
import { createDevice, transitionDeviceLifecycle, updateDevice } from "@/src/lib/session";

const deviceTypes = ["switch", "router", "firewall", "server", "printer", "access_point", "unknown"] as const;
const lifecycles = ["discovered", "pending_review", "managed", "unmanaged", "maintenance", "retired", "archived"] as const;

const IdentifierSchema = v.object({
  serial: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  mac: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(64))),
  hostname: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  assetTag: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
});

const CreateSchema = v.object({
  siteId: v.pipe(v.string(), v.uuid()),
  deviceType: v.picklist(deviceTypes),
  displayName: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  vendor: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  model: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  description: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(4000))),
  operationalOwner: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  identifiers: IdentifierSchema,
});

const UpdateSchema = v.object({
  siteId: v.pipe(v.string(), v.uuid()),
  deviceId: v.pipe(v.string(), v.uuid()),
  expectedVersion: v.pipe(v.string(), v.regex(/^\d+$/)),
  deviceType: v.picklist(deviceTypes),
  displayName: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  hostname: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  vendor: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  model: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  osName: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  osVersion: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  firmwareVersion: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
  description: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(4000))),
  operationalOwner: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(255))),
});

const LifecycleSchema = v.object({
  siteId: v.pipe(v.string(), v.uuid()),
  deviceId: v.pipe(v.string(), v.uuid()),
  expectedVersion: v.pipe(v.string(), v.regex(/^\d+$/)),
  next: v.picklist(lifecycles),
  reason: v.optional(v.pipe(v.string(), v.trim(), v.maxLength(2000))),
});

export async function createDeviceAction(formData: FormData) {
  const parsed = v.safeParse(CreateSchema, {
    siteId: field(formData, "siteId"),
    deviceType: field(formData, "deviceType"),
    displayName: optionalField(formData, "displayName"),
    vendor: optionalField(formData, "vendor"),
    model: optionalField(formData, "model"),
    description: optionalField(formData, "description"),
    operationalOwner: optionalField(formData, "operationalOwner"),
    identifiers: {
      serial: optionalField(formData, "serial"),
      mac: optionalField(formData, "mac"),
      hostname: optionalField(formData, "hostname"),
      assetTag: optionalField(formData, "assetTag"),
    },
  });
  const siteId = field(formData, "siteId");
  if (!parsed.success) redirectWithError("/inventory/new", siteId, "invalid_device_input");

  const identifiers = buildIdentifiers(parsed.output.identifiers);
  if (identifiers.length === 0) redirectWithError("/inventory/new", parsed.output.siteId, "identifier_required");

  const input: NewDevice = {
    deviceType: parsed.output.deviceType as DeviceType,
    capabilities: [],
    identifiers,
    ...optionalProperty("displayName", parsed.output.displayName),
    ...optionalProperty("hostname", parsed.output.identifiers.hostname),
    ...optionalProperty("vendor", parsed.output.vendor),
    ...optionalProperty("model", parsed.output.model),
    ...optionalProperty("description", parsed.output.description),
    ...optionalProperty("operationalOwner", parsed.output.operationalOwner),
  };
  const result = await createDevice(parsed.output.siteId, input);
  if (!result.ok) redirectWithError("/inventory/new", parsed.output.siteId, result.error.code);

  revalidatePath("/inventory");
  redirect(`/inventory/${result.data.id}?site=${parsed.output.siteId}`);
}

export async function updateDeviceAction(formData: FormData) {
  const parsed = v.safeParse(UpdateSchema, {
    siteId: field(formData, "siteId"),
    deviceId: field(formData, "deviceId"),
    expectedVersion: field(formData, "expectedVersion"),
    deviceType: field(formData, "deviceType"),
    displayName: optionalField(formData, "displayName"),
    hostname: optionalField(formData, "hostname"),
    vendor: optionalField(formData, "vendor"),
    model: optionalField(formData, "model"),
    osName: optionalField(formData, "osName"),
    osVersion: optionalField(formData, "osVersion"),
    firmwareVersion: optionalField(formData, "firmwareVersion"),
    description: optionalField(formData, "description"),
    operationalOwner: optionalField(formData, "operationalOwner"),
  });
  const siteId = field(formData, "siteId");
  const deviceId = field(formData, "deviceId");
  if (!parsed.success) redirectDeviceWithError(siteId, deviceId, "invalid_device_input");

  const input: UpdateDeviceRequest = {
    expectedVersion: Number(parsed.output.expectedVersion),
    deviceType: parsed.output.deviceType as DeviceType,
    displayName: parsed.output.displayName || null,
    hostname: parsed.output.hostname || null,
    vendor: parsed.output.vendor || null,
    model: parsed.output.model || null,
    osName: parsed.output.osName || null,
    osVersion: parsed.output.osVersion || null,
    firmwareVersion: parsed.output.firmwareVersion || null,
    description: parsed.output.description || null,
    operationalOwner: parsed.output.operationalOwner || null,
  };
  const result = await updateDevice(parsed.output.siteId, parsed.output.deviceId, input);
  if (!result.ok) redirectDeviceWithError(parsed.output.siteId, parsed.output.deviceId, result.error.code);

  revalidatePath("/inventory");
  revalidatePath(`/inventory/${parsed.output.deviceId}`);
  redirect(`/inventory/${parsed.output.deviceId}?site=${parsed.output.siteId}&saved=1`);
}

export async function transitionLifecycleAction(formData: FormData) {
  const parsed = v.safeParse(LifecycleSchema, {
    siteId: field(formData, "siteId"),
    deviceId: field(formData, "deviceId"),
    expectedVersion: field(formData, "expectedVersion"),
    next: field(formData, "next"),
    reason: optionalField(formData, "reason"),
  });
  const siteId = field(formData, "siteId");
  const deviceId = field(formData, "deviceId");
  if (!parsed.success) redirectDeviceWithError(siteId, deviceId, "invalid_lifecycle_transition");

  const result = await transitionDeviceLifecycle(parsed.output.siteId, parsed.output.deviceId, {
    expectedVersion: Number(parsed.output.expectedVersion),
    next: parsed.output.next as DeviceLifecycle,
    ...(parsed.output.reason ? { reason: parsed.output.reason } : {}),
  });
  if (!result.ok) redirectDeviceWithError(parsed.output.siteId, parsed.output.deviceId, result.error.code);

  revalidatePath("/inventory");
  revalidatePath(`/inventory/${parsed.output.deviceId}`);
  redirect(`/inventory/${parsed.output.deviceId}?site=${parsed.output.siteId}&saved=1`);
}

function buildIdentifiers(value: v.InferOutput<typeof IdentifierSchema>): DeviceIdentifierInput[] {
  const identifiers: DeviceIdentifierInput[] = [];
  if (value.serial) identifiers.push({ kind: "serial", value: value.serial, source: "manual" });
  if (value.mac) identifiers.push({ kind: "mac", value: value.mac, source: "manual" });
  if (value.hostname) identifiers.push({ kind: "hostname", value: value.hostname, source: "manual" });
  if (value.assetTag) identifiers.push({ kind: "asset_tag", value: value.assetTag, source: "manual" });
  return identifiers;
}

function optionalProperty<K extends string>(key: K, value: string | undefined) {
  return value ? { [key]: value } as Record<K, string> : {};
}

function field(formData: FormData, name: string) {
  const value = formData.get(name);
  return typeof value === "string" ? value : "";
}

function optionalField(formData: FormData, name: string) {
  const value = field(formData, name).trim();
  return value || undefined;
}

function redirectWithError(path: string, siteId: string, code: string): never {
  const query = new URLSearchParams({ site: siteId, error: code });
  redirect(`${path}?${query.toString()}`);
}

function redirectDeviceWithError(siteId: string, deviceId: string, code: string): never {
  const query = new URLSearchParams({ site: siteId, error: code });
  redirect(`/inventory/${deviceId}?${query.toString()}`);
}
