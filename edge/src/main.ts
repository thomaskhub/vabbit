// Bunny Edge Script entry point. One deployed script = one network.
//
// Environment variables / secrets (set in the Bunny dashboard):
//   ADMIN_TOKEN_SHA256  (secret)  hex SHA-256 of the admin token (`edgeguard admin-token`)
//   STORAGE_ZONE                  Bunny Storage zone name holding this network's state
//   STORAGE_ACCESS_KEY  (secret)  that storage zone's password (FTP & API access key)
//   STORAGE_HOST                  optional, e.g. ny.storage.bunnycdn.com (default storage.bunnycdn.com)
//   NETWORK_CIDR                  optional, default 100.92.0.0/16
//   NETWORK_NAME                  optional, default "edgeguard"

import * as BunnySDK from "https://esm.sh/@bunny.net/edgescript-sdk@0.12.1";
import process from "node:process";
import { createHandler } from "./handler.ts";
import { BunnyStorage } from "./store.ts";

function env(name: string): string | undefined {
  const v = process.env[name];
  return v === undefined || v === "" ? undefined : v.trim();
}

function required(name: string): string {
  const v = env(name);
  if (!v) throw new Error(`missing environment variable ${name}`);
  return v;
}

let handler: (req: Request) => Promise<Response>;
try {
  handler = createHandler(
    new BunnyStorage({
      zone: required("STORAGE_ZONE"),
      accessKey: required("STORAGE_ACCESS_KEY"),
      host: env("STORAGE_HOST"),
    }),
    {
      adminTokenSha256: required("ADMIN_TOKEN_SHA256").toLowerCase(),
      networkCidr: env("NETWORK_CIDR") ?? "100.92.0.0/16",
      networkName: env("NETWORK_NAME") ?? "edgeguard",
    },
  );
} catch (e) {
  // Fail closed: never serve with a half-configured network.
  console.error("edgeguard misconfigured:", (e as Error).message);
  handler = async () =>
    new Response(JSON.stringify({ error: "server misconfigured" }), {
      status: 503,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
}

BunnySDK.net.http.serve(handler);
