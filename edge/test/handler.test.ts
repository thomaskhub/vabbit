import { describe, expect, test } from "bun:test";
import { computePeers, createHandler, type Device, optEndpoint } from "../src/handler.ts";
import { sha256Hex } from "../src/crypto.ts";
import { MemoryStore } from "../src/store.ts";

const ADMIN = "ega_" + "A".repeat(43);
const KEY1 = "Ag3x3mJ0bWg3J7Ff2x7bX9H1t2Y8l9l3v0QkzQ9dQ3w=";
const KEY2 = "bR8t1H4l2vN6pK0yW3qZ9cX5mJ7dF1sA2gE4hT6uY8o=";
const KEY3 = "cC3t1H4l2vN6pK0yW3qZ9cX5mJ7dF1sA2gE4hT6uY8o=";

async function setup(now = { t: 1_700_000_000_000 }) {
  const store = new MemoryStore();
  const h = createHandler(store, {
    adminTokenSha256: await sha256Hex(ADMIN),
    networkCidr: "100.92.0.0/24",
    networkName: "test",
    now: () => now.t,
  });
  const call = async (method: string, path: string, body?: unknown, token?: string) => {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await h(
      new Request(`https://net.example${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
      }),
    );
    return { status: res.status, body: (await res.json()) as any, headers: res.headers };
  };
  return { store, call, now };
}

describe("admin auth", () => {
  test("rejects missing and wrong tokens", async () => {
    const { call } = await setup();
    expect((await call("GET", "/api/v1/network")).status).toBe(401);
    expect((await call("GET", "/api/v1/network", undefined, "ega_" + "B".repeat(43))).status).toBe(401);
    const ok = await call("GET", "/api/v1/network", undefined, ADMIN);
    expect(ok.status).toBe(200);
    expect(ok.body).toEqual({ name: "test", cidr: "100.92.0.0/24" });
    expect(ok.headers.get("cache-control")).toBe("no-store");
  });

  test("device tokens are not admin tokens", async () => {
    const { call } = await setup();
    const key = (await call("POST", "/api/v1/setup-keys", {}, ADMIN)).body.key;
    const enr = await call("POST", "/api/v1/enroll", { setupKey: key, name: "a", publicKey: KEY1 });
    expect((await call("GET", "/api/v1/devices", undefined, enr.body.deviceToken)).status).toBe(401);
  });
});

describe("setup keys", () => {
  test("one-time key works once", async () => {
    const { call } = await setup();
    const k = await call("POST", "/api/v1/setup-keys", {}, ADMIN);
    expect(k.status).toBe(201);
    expect(k.body.key).toMatch(/^egk_[A-Za-z0-9_-]{43}$/);
    const a = await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "a", publicKey: KEY1 });
    expect(a.status).toBe(201);
    const b = await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "b", publicKey: KEY2 });
    expect(b.status).toBe(401);
    expect((await call("GET", "/api/v1/setup-keys", undefined, ADMIN)).body.setupKeys).toHaveLength(0);
  });

  test("expired keys are rejected", async () => {
    const { call, now } = await setup();
    const k = await call("POST", "/api/v1/setup-keys", { ttlSeconds: 60 }, ADMIN);
    now.t += 61_000;
    const a = await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "a", publicKey: KEY1 });
    expect(a.status).toBe(401);
    expect(a.body.error).toBe("setup key expired");
  });

  test("reusable key with limit, and revoke", async () => {
    const { call } = await setup();
    const k = await call("POST", "/api/v1/setup-keys", { reusable: true, maxUses: 2 }, ADMIN);
    expect((await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "a", publicKey: KEY1 })).status).toBe(201);
    expect((await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "b", publicKey: KEY2 })).status).toBe(201);
    expect((await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "c", publicKey: KEY3 })).status).toBe(401);

    const k2 = await call("POST", "/api/v1/setup-keys", { reusable: true }, ADMIN);
    expect((await call("DELETE", `/api/v1/setup-keys/${k2.body.id}`, undefined, ADMIN)).status).toBe(200);
    expect((await call("POST", "/api/v1/enroll", { setupKey: k2.body.key, name: "c", publicKey: KEY3 })).status).toBe(401);
  });

  test("invalid input does not consume the key", async () => {
    const { call } = await setup();
    const k = await call("POST", "/api/v1/setup-keys", {}, ADMIN);
    expect((await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "bad name!", publicKey: KEY1 })).status).toBe(400);
    expect((await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "a", publicKey: "nope" })).status).toBe(400);
    expect((await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "a", publicKey: KEY1 })).status).toBe(201);
  });
});

describe("devices and sync", () => {
  async function enroll(call: any, name: string, publicKey: string, extra: object = {}) {
    const key = (await call("POST", "/api/v1/setup-keys", {}, ADMIN)).body.key;
    const r = await call("POST", "/api/v1/enroll", { setupKey: key, name, publicKey, ...extra });
    expect(r.status).toBe(201);
    return r.body;
  }

  test("enroll assigns unique IPs in the CIDR and rejects duplicate keys", async () => {
    const { call } = await setup();
    const a = await enroll(call, "a", KEY1);
    const b = await enroll(call, "b", KEY2);
    expect(a.device.ip).toMatch(/^100\.92\.0\.\d+$/);
    expect(a.device.ip).not.toBe(b.device.ip);
    expect(a.deviceToken).toMatch(/^egd_[0-9a-f]{16}\.[A-Za-z0-9_-]{43}$/);
    const key = (await call("POST", "/api/v1/setup-keys", {}, ADMIN)).body.key;
    expect((await call("POST", "/api/v1/enroll", { setupKey: key, name: "dup", publicKey: KEY1 })).status).toBe(409);
  });

  test("sync returns peers; removed device loses access and disappears", async () => {
    const { call } = await setup();
    const a = await enroll(call, "a", KEY1, { endpoint: "203.0.113.5:51820" });
    const b = await enroll(call, "b", KEY2);

    const sa = await call("POST", "/api/v1/sync", { endpoint: "203.0.113.5:51820" }, a.deviceToken);
    expect(sa.status).toBe(200);
    expect(sa.body.address).toBe(`${a.device.ip}/24`);
    expect(sa.body.peers).toEqual([{ name: "b", publicKey: KEY2, allowedIPs: [`${b.device.ip}/32`] }]);

    const sb = await call("POST", "/api/v1/sync", {}, b.deviceToken);
    expect(sb.body.peers).toEqual([
      { name: "a", publicKey: KEY1, allowedIPs: [`${a.device.ip}/32`], endpoint: "203.0.113.5:51820", persistentKeepalive: 25 },
    ]);

    expect((await call("DELETE", `/api/v1/devices/${b.device.id}`, undefined, ADMIN)).status).toBe(200);
    expect((await call("POST", "/api/v1/sync", {}, b.deviceToken)).status).toBe(401);
    expect((await call("POST", "/api/v1/sync", { endpoint: "203.0.113.5:51820" }, a.deviceToken)).body.peers).toEqual([]);
  });

  test("a device can remove itself", async () => {
    const { call } = await setup();
    const a = await enroll(call, "a", KEY1);
    expect((await call("DELETE", "/api/v1/device", undefined, a.deviceToken)).status).toBe(200);
    expect((await call("POST", "/api/v1/sync", {}, a.deviceToken)).status).toBe(401);
    expect((await call("GET", "/api/v1/devices", undefined, ADMIN)).body.devices).toEqual([]);
  });

  test("forged device token is rejected", async () => {
    const { call } = await setup();
    const a = await enroll(call, "a", KEY1);
    const forged = a.deviceToken.slice(0, -1) + (a.deviceToken.endsWith("A") ? "B" : "A");
    expect((await call("POST", "/api/v1/sync", {}, forged)).status).toBe(401);
  });

  test("only the admin can make a hub, and it needs an endpoint", async () => {
    const { call } = await setup();
    const key = (await call("POST", "/api/v1/setup-keys", {}, ADMIN)).body.key;
    const r = await call("POST", "/api/v1/enroll", { setupKey: key, name: "h", publicKey: KEY1, hub: true });
    expect(r.status).toBe(400);
    const a = await enroll(call, "a", KEY1);
    // A device asking to be hub via sync is ignored.
    const s = await call("POST", "/api/v1/sync", { endpoint: "203.0.113.5:51820", hub: true }, a.deviceToken);
    expect(s.body.self.hub).toBe(false);
    expect((await call("PATCH", `/api/v1/devices/${a.device.id}`, { hub: true }, a.deviceToken)).status).toBe(401);
    expect((await call("PATCH", `/api/v1/devices/${a.device.id}`, { hub: true }, ADMIN)).body.device.hub).toBe(true);
    // Dropping the endpoint drops hub status.
    expect((await call("POST", "/api/v1/sync", {}, a.deviceToken)).body.self.hub).toBe(false);
    const b = await enroll(call, "b", KEY2);
    expect((await call("PATCH", `/api/v1/devices/${b.device.id}`, { hub: true }, ADMIN)).status).toBe(400);
  });

  test("rejects oversized and malformed bodies", async () => {
    const { call } = await setup();
    expect((await call("POST", "/api/v1/setup-keys", "x".repeat(9000), ADMIN)).status).toBe(413);
    expect((await call("POST", "/api/v1/setup-keys", "{nope", ADMIN)).status).toBe(400);
    expect((await call("POST", "/api/v1/setup-keys", "[]", ADMIN)).status).toBe(400);
  });
});

describe("computePeers", () => {
  const dev = (id: string, endpoint: string | null, hub = false): Device => ({
    id, name: id, publicKey: id, ip: `100.92.0.${id.charCodeAt(0) - 96}`, endpoint, hub,
    tokenHash: "", createdAt: 0, lastSeen: 0,
  });

  test("NATed devices route the network via the hub and skip each other", () => {
    const hub = dev("h", "198.51.100.1:51820", true);
    const pub = dev("p", "198.51.100.2:51820");
    const n1 = dev("a", null);
    const n2 = dev("b", null);
    const all = [hub, pub, n1, n2];
    const peers = computePeers(n1, all, "100.92.0.0/24");
    expect(peers.map((p) => [p.name, p.allowedIPs])).toEqual([
      ["h", ["100.92.0.0/24"]],
      ["p", [`${pub.ip}/32`]],
    ]);
    expect(peers.every((p) => p.persistentKeepalive === 25)).toBe(true);
    // The hub knows everyone as a /32 and dials nobody without an endpoint.
    const hp = computePeers(hub, all, "100.92.0.0/24");
    expect(hp.map((p) => p.allowedIPs[0])).toEqual([`${pub.ip}/32`, `${n1.ip}/32`, `${n2.ip}/32`]);
    expect(hp.find((p) => p.name === "a")!.endpoint).toBeUndefined();
  });
});

describe("optEndpoint", () => {
  test("validates host:port", () => {
    expect(optEndpoint("1.2.3.4:51820")).toBe("1.2.3.4:51820");
    expect(optEndpoint("[2001:db8::1]:51820")).toBe("[2001:db8::1]:51820");
    expect(optEndpoint("vpn.example.com:443")).toBe("vpn.example.com:443");
    expect(optEndpoint(undefined)).toBeNull();
    for (const bad of ["1.2.3.4", "1.2.3.400:1", "a:0", "a:70000", "-a.com:1", "a b:1", "x".repeat(300)]) {
      expect(() => optEndpoint(bad)).toThrow();
    }
  });
});
