// The Vabbit control plane as a Cloudflare Worker (ES module). State lives in an R2 bucket.
//
// Bindings:
//   NETWORK_BUCKET      R2 bucket binding (private; holds devices/ and setup-keys/)
//   ADMIN_TOKEN_SHA256  secret: SHA-256 of the admin token (`vabbit admin-token` prints it)
//   NETWORK_CIDR        optional variable, default 100.92.0.0/16
//   NETWORK_NAME        optional variable, shown in the CLI
//
// Build: `bun run build:worker` -> dist/worker.js. Deploy by hand with wrangler, see docs/DEPLOY.md.

import { createHandler } from "./handler.ts";
import { R2Store, type R2BucketLike } from "./r2store.ts";

export interface Env {
  NETWORK_BUCKET: R2BucketLike;
  ADMIN_TOKEN_SHA256: string;
  NETWORK_CIDR?: string;
  NETWORK_NAME?: string;
}

let cached:
  | { bucket: R2BucketLike; hash: string; cidr: string; name: string; handler: (req: Request) => Promise<Response> }
  | undefined;

function handlerFor(env: Env): (req: Request) => Promise<Response> {
  const hash = (env.ADMIN_TOKEN_SHA256 ?? "").trim().toLowerCase();
  const cidr = env.NETWORK_CIDR?.trim() || "100.92.0.0/16";
  const name = env.NETWORK_NAME?.trim() || "vabbit";
  if (!env.NETWORK_BUCKET) throw new Error("missing R2 binding NETWORK_BUCKET");
  if (cached && cached.bucket === env.NETWORK_BUCKET && cached.hash === hash && cached.cidr === cidr && cached.name === name) {
    return cached.handler;
  }
  const handler = createHandler(new R2Store(env.NETWORK_BUCKET), { adminTokenSha256: hash, networkCidr: cidr, networkName: name });
  cached = { bucket: env.NETWORK_BUCKET, hash, cidr, name, handler };
  return handler;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    let handler: (req: Request) => Promise<Response>;
    try {
      handler = handlerFor(env);
    } catch (e) {
      // Fail closed: never serve with a half-configured network. The reason goes to the log, not to the caller.
      console.error("vabbit misconfigured:", (e as Error).message);
      return new Response(JSON.stringify({ error: "server misconfigured" }), {
        status: 503,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
      });
    }
    return handler(req);
  },
};
