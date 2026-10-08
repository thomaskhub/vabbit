import { describe, expect, test } from "bun:test";
import worker, { type Env } from "../src/worker.ts";
import { createHandler } from "../src/handler.ts";
import { sha256Hex } from "../src/crypto.ts";
import { R2Store } from "../src/r2store.ts";
import { FakeR2 } from "./fake-r2.ts";

const ADMIN = "vba_" + "A".repeat(43);
const KEY1 = "Ag3x3mJ0bWg3J7Ff2x7bX9H1t2Y8l9l3v0QkzQ9dQ3w=";
const KEY2 = "bR8t1H4l2vN6pK0yW3qZ9cX5mJ7dF1sA2gE4hT6uY8o=";

async function env(extra: Partial<Env> = {}): Promise<Env> {
  return { NETWORK_BUCKET: new FakeR2(), ADMIN_TOKEN_SHA256: await sha256Hex(ADMIN), NETWORK_NAME: "pilot", NETWORK_CIDR: "100.93.0.0/24", ...extra };
}

async function call(e: Env, method: string, path: string, body?: unknown, token?: string) {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await worker.fetch(
    new Request(`https://net.example${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }),
    e,
  );
  return { status: res.status, body: (await res.json()) as any };
}

describe("worker entry", () => {
  test("serves the API on the bucket binding, with the configured name and range", async () => {
    const e = await env();
    expect((await call(e, "GET", "/api/v1/network")).status).toBe(401);
    const ok = await call(e, "GET", "/api/v1/network", undefined, ADMIN);
    expect(ok.status).toBe(200);
    expect(ok.body.name).toBe("pilot");
    expect(ok.body.cidr).toBe("100.93.0.0/24");
  });

  test("defaults for the optional variables", async () => {
    const e = await env({ NETWORK_NAME: undefined, NETWORK_CIDR: undefined });
    const ok = await call(e, "GET", "/api/v1/network", undefined, ADMIN);
    expect(ok.body.name).toBe("vabbit");
    expect(ok.body.cidr).toBe("100.92.0.0/16");
  });

  test("fails closed without the secret or with a bad one, and says nothing about why", async () => {
    for (const bad of [undefined, "", "not-a-hash", "G".repeat(64)]) {
      const e = await env({ ADMIN_TOKEN_SHA256: bad as any });
      const r = await call(e, "GET", "/api/v1/network", undefined, ADMIN);
      expect(r.status).toBe(503);
      expect(r.body).toEqual({ error: "server misconfigured" });
    }
  });

  test("fails closed without the bucket binding", async () => {
    const e = await env({ NETWORK_BUCKET: undefined as any });
    expect((await call(e, "POST", "/api/v1/setup-keys", {}, ADMIN)).status).toBe(503);
  });

  test("an upper-case hash is accepted (as on the Bunny script)", async () => {
    const e = await env({ ADMIN_TOKEN_SHA256: (await sha256Hex(ADMIN)).toUpperCase() });
    expect((await call(e, "GET", "/api/v1/network", undefined, ADMIN)).status).toBe(200);
  });

  test("state lives in the bucket: a second isolate with the same bucket sees it", async () => {
    const e1 = await env();
    const k = await call(e1, "POST", "/api/v1/setup-keys", {}, ADMIN);
    expect(k.status).toBe(201);
    const e2 = { ...e1, NETWORK_NAME: "other-isolate" }; // different config key: a new handler, the same bucket
    expect((await call(e2, "GET", "/api/v1/setup-keys", undefined, ADMIN)).body.setupKeys).toHaveLength(1);
  });
});

describe("a full flow on the R2 store", () => {
  test("setup key, enroll two devices, sync, remove", async () => {
    const r2 = new FakeR2();
    const h = createHandler(new R2Store(r2), { adminTokenSha256: await sha256Hex(ADMIN), networkCidr: "100.92.0.0/24", networkName: "t" });
    const call2 = async (method: string, path: string, body?: unknown, token?: string) => {
      const headers: Record<string, string> = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      const res = await h(new Request(`https://net.example${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }));
      return { status: res.status, body: (await res.json()) as any };
    };
    const key = (await call2("POST", "/api/v1/setup-keys", { reusable: true }, ADMIN)).body.key;
    const a = (await call2("POST", "/api/v1/enroll", { setupKey: key, name: "a", publicKey: KEY1 })).body;
    const b = (await call2("POST", "/api/v1/enroll", { setupKey: key, name: "b", publicKey: KEY2 })).body;
    expect(a.device.ip).not.toBe(b.device.ip);
    const sa = await call2("POST", "/api/v1/sync", { candidates: ["198.51.100.9:40001"] }, a.deviceToken);
    expect(sa.body.peers.map((p: any) => p.name)).toEqual(["b"]);
    const sb = await call2("POST", "/api/v1/sync", {}, b.deviceToken);
    expect(sb.body.peers[0].endpoints).toEqual(["198.51.100.9:40001"]);
    expect([...r2.data.keys()].every((k) => /^(devices|setup-keys)\/[A-Za-z0-9_-]+\.json$/.test(k))).toBe(true);
    expect((await call2("DELETE", `/api/v1/devices/${b.device.id}`, undefined, ADMIN)).status).toBe(200);
    expect((await call2("POST", "/api/v1/sync", {}, b.deviceToken)).status).toBe(401);
    // the bucket holds no token or key in clear text
    const all = [...r2.data.values()].join("\n");
    expect(all).not.toContain(key);
    expect(all).not.toContain(b.deviceToken);
  });
});

describe("the Worker bundle", () => {
  test("builds as an ES module with a default export and no Node-only code", async () => {
    const out = await Bun.build({ entrypoints: [`${import.meta.dir}/../src/worker.ts`], target: "browser", format: "esm" });
    expect(out.success).toBe(true);
    const text = await out.outputs[0].text();
    expect(text).toMatch(/export\s*\{[^}]*\bdefault\b/);
    for (const [what, re] of [["node: imports", /node:/], ["process", /\bprocess\./], ["Buffer", /\bBuffer\b/], ["require()", /\brequire\(/], ["remote imports", /https?:\/\/[^"'\s]*\.(js|ts|mjs)/]] as const) {
      expect(text, what).not.toMatch(re);
    }
    expect(text.length).toBeLessThan(200 * 1024);
  });
});
