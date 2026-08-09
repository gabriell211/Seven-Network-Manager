import { readFileSync } from "node:fs";

const roadmap = readFileSync(new URL("../docs/roadmap.yaml", import.meta.url), "utf8");
const required = ["C0", "C1", "C2", "C3", "RELEASE_TRIAL", "119", "Trial nao contorna RBAC"];

const missing = required.filter((token) => !roadmap.includes(token));

if (missing.length > 0) {
  console.error(`Roadmap validation failed. Missing: ${missing.join(", ")}`);
  process.exit(1);
}

console.log("Roadmap validation passed.");
