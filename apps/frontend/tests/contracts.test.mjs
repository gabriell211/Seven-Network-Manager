import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = process.cwd();
const spec = JSON.parse(readFileSync(join(root, "public/openapi-v1.json"), "utf8"));

const requiredPaths = [
  "/system",
  "/context",
  "/auth/login",
  "/auth/me",
  "/sites/{siteId}/devices",
  "/sites/{siteId}/devices/{deviceId}",
  "/sites/{siteId}/devices/{deviceId}/lifecycle",
  "/sites/{siteId}/ipam/prefixes",
  "/sites/{siteId}/ipam/prefixes/{prefixId}",
  "/sites/{siteId}/ipam/addresses",
  "/sites/{siteId}/ipam/addresses/{addressId}",
];

test("versioned OpenAPI contract exposes the implemented control-plane surface", () => {
  assert.equal(spec.openapi, "3.1.0");
  for (const path of requiredPaths) assert.ok(spec.paths[path], `missing ${path}`);
  const error = spec.components.schemas.ErrorEnvelope;
  assert.deepEqual(error.required, ["code", "message"]);
  assert.ok(error.properties.requestId);
  assert.ok(spec.components.schemas.SiteContext.properties.routingDomains);
  assert.deepEqual(spec.components.schemas.AddressState.enum, ["available", "reserved", "assigned", "observed", "conflict", "excluded"]);
});

test("frontend consumes generated contract types instead of handwritten primary DTOs", () => {
  const api = readFileSync(join(root, "src/lib/api.ts"), "utf8");
  const session = readFileSync(join(root, "src/lib/session.ts"), "utf8");
  assert.match(api, /src\/generated\/api-contract/);
  assert.match(session, /src\/generated\/api-contract/);
  assert.doesNotMatch(api, /interface\s+SystemStatus/);
  assert.doesNotMatch(session, /interface\s+Device\b/);
  assert.doesNotMatch(session, /interface\s+IpPrefix\b/);
});

test("browser/application source does not import direct LAN execution primitives", () => {
  const files = collect(join(root, "app")).concat(collect(join(root, "src")));
  const forbidden = [/from ["']node:net["']/, /from ["']node:dgram["']/, /child_process/, /TcpStream/, /raw-socket/];
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    for (const pattern of forbidden) assert.doesNotMatch(source, pattern, `${file} crosses execution boundary`);
  }
});

test("unimplemented modules are not exposed through generic placeholder pages", () => {
  assert.equal(existsSync(join(root, "app/discovery/page.tsx")), false);
  assert.equal(existsSync(join(root, "app/telemetry/page.tsx")), false);
  assert.equal(existsSync(join(root, "src/components/module-page.tsx")), false);
  assert.equal(existsSync(join(root, "app/ipam/page.tsx")), true, "IPAM only returns after its real contract exists");
});

test("brand and application SVG assets are versioned", () => {
  for (const asset of [
    "public/brand/seven-mark.svg",
    "public/brand/seven-network-manager.svg",
    "app/icon.svg",
  ]) assert.ok(existsSync(join(root, asset)), `missing ${asset}`);
});

function collect(directory) {
  const output = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) output.push(...collect(path));
    else if (/\.(ts|tsx)$/.test(path)) output.push(path);
  }
  return output;
}
