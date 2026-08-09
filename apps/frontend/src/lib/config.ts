import * as v from "valibot";

const ServerConfigSchema = v.object({
  apiBaseUrl: v.pipe(v.string(), v.url()),
});

export type ServerConfig = v.InferOutput<typeof ServerConfigSchema>;

export function getServerConfig(): ServerConfig {
  return v.parse(ServerConfigSchema, {
    apiBaseUrl: process.env.SNM_API_BASE_URL ?? "http://127.0.0.1:8080",
  });
}
