// Local development server (bun run dev). In-memory storage, nothing persisted.
// Never use in production.

import { createHandler } from "./handler.ts";
import { MemoryStore } from "./store.ts";

const adminTokenSha256 = process.env.ADMIN_TOKEN_SHA256;
if (!adminTokenSha256) {
  console.error("set ADMIN_TOKEN_SHA256 (see `edgeguard admin-token`)");
  process.exit(1);
}
const port = Number(process.env.PORT ?? 8787);
const handler = createHandler(new MemoryStore(), {
  adminTokenSha256,
  networkCidr: process.env.NETWORK_CIDR ?? "100.92.0.0/16",
  networkName: process.env.NETWORK_NAME ?? "dev",
});
// Optional TLS (TLS_CERT / TLS_KEY file paths) for testing clients on other hosts.
const tls = process.env.TLS_CERT && process.env.TLS_KEY
  ? { cert: Bun.file(process.env.TLS_CERT), key: Bun.file(process.env.TLS_KEY) }
  : undefined;
const hostname = process.env.HOST ?? "127.0.0.1";
Bun.serve({ port, hostname, fetch: handler, tls });
console.log(`edgeguard dev server on ${tls ? "https" : "http"}://${hostname}:${port}`);
