import { describe, expect, test } from "bun:test";
import { computePeers, createHandler, type Device, optEndpoint } from "../src/handler.ts";
import { sha256Hex } from "../src/crypto.ts";
import { MemoryStore } from "../src/store.ts";

const ADMIN = "vba_" + "A".repeat(43);
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
    expect((await call("GET", "/api/v1/network", undefined, "vba_" + "B".repeat(43))).status).toBe(401);
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
    expect(k.body.key).toMatch(/^vbk_[A-Za-z0-9_-]{43}$/);
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

  test("never-expiring key and expiring devices", async () => {
    const { call, now } = await setup();
    const k = await call("POST", "/api/v1/setup-keys", { reusable: true, ttlSeconds: 0, deviceTtlSeconds: 3600 }, ADMIN);
    expect(k.body.expiresAt).toBeNull();
    now.t += 5 * 365 * 24 * 3600 * 1000; // years later the key still works
    const a = await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "guest", publicKey: KEY1 });
    expect(a.status).toBe(201);
    expect(a.body.device.expiresAt).toBe(new Date(now.t + 3600_000).toISOString());
    const plain = (await call("POST", "/api/v1/setup-keys", {}, ADMIN)).body.key;
    const b = await call("POST", "/api/v1/enroll", { setupKey: plain, name: "b", publicKey: KEY2 });
    expect(b.body.device.expiresAt).toBeNull();
    expect((await call("POST", "/api/v1/sync", {}, b.body.deviceToken)).body.peers).toHaveLength(1);

    now.t += 3601_000;
    // The guest is gone from everyone's peer list and loses access itself.
    expect((await call("POST", "/api/v1/sync", {}, b.body.deviceToken)).body.peers).toHaveLength(0);
    const s = await call("POST", "/api/v1/sync", {}, a.body.deviceToken);
    expect(s.status).toBe(401);
    expect(s.body.error).toBe("device access expired");

    // Admin can set and clear an end date later; revoking the key stops new joins.
    const bid = b.body.device.id;
    expect((await call("PATCH", `/api/v1/devices/${bid}`, { expiresInSeconds: 600 }, ADMIN)).body.device.expiresAt).not.toBeNull();
    expect((await call("PATCH", `/api/v1/devices/${bid}`, { expiresInSeconds: null }, ADMIN)).body.device.expiresAt).toBeNull();
    await call("DELETE", `/api/v1/setup-keys/${k.body.id}`, undefined, ADMIN);
    expect((await call("POST", "/api/v1/enroll", { setupKey: k.body.key, name: "c", publicKey: KEY3 })).status).toBe(401);
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
    expect(a.deviceToken).toMatch(/^vbd_[0-9a-f]{16}\.[A-Za-z0-9_-]{43}$/);
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
    expect(sa.body.peers).toEqual([{ name: "b", publicKey: KEY2, ip: b.device.ip, hub: false, endpoints: [] }]);

    // b reports NAT traversal candidates; a sees them, a's static endpoint first.
    const cands = ["198.51.100.9:40001", "192.168.1.20:51820"];
    const sb = await call("POST", "/api/v1/sync", { candidates: cands }, b.deviceToken);
    expect(sb.body.peers).toEqual([
      { name: "a", publicKey: KEY1, ip: a.device.ip, hub: false, endpoints: ["203.0.113.5:51820"] },
    ]);
    const sa2 = await call("POST", "/api/v1/sync", { endpoint: "203.0.113.5:51820", candidates: ["203.0.113.5:51820", "10.0.0.2:51820"] }, a.deviceToken);
    expect(sa2.body.peers[0].endpoints).toEqual(cands);
    const sb2 = await call("POST", "/api/v1/sync", { candidates: cands }, b.deviceToken);
    expect(sb2.body.peers[0].endpoints).toEqual(["203.0.113.5:51820", "10.0.0.2:51820"]);
    // A sync without candidates (e.g. `vabbit status`) keeps the stored ones.
    await call("POST", "/api/v1/sync", {}, b.deviceToken);
    const sa3 = await call("POST", "/api/v1/sync", { endpoint: "203.0.113.5:51820" }, a.deviceToken);
    expect(sa3.body.peers[0].endpoints).toEqual(cands);

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

  test("only a hub's TCP relay is published", async () => {
    const { call } = await setup();
    const fp = "ab".repeat(32);
    const h = await enroll(call, "h", KEY1, { endpoint: "203.0.113.1:51820" });
    const a = await enroll(call, "a", KEY2);
    const relay = { addr: "203.0.113.1:443", fingerprint: fp };
    await call("POST", "/api/v1/sync", { endpoint: "203.0.113.1:51820", relay }, h.deviceToken);
    // Not a hub yet: no relay handed out.
    expect((await call("POST", "/api/v1/sync", {}, a.deviceToken)).body.peers[0].relay).toBeUndefined();
    await call("PATCH", `/api/v1/devices/${h.device.id}`, { hub: true }, ADMIN);
    expect((await call("POST", "/api/v1/sync", {}, a.deviceToken)).body.peers[0].relay).toEqual(relay);
    for (const bad of [{ addr: "x", fingerprint: fp }, { addr: "1.2.3.4:443", fingerprint: "zz" }, "str"]) {
      expect((await call("POST", "/api/v1/sync", { relay: bad }, h.deviceToken)).status).toBe(400);
    }
  });

  test("rejects bad candidates", async () => {
    const { call } = await setup();
    const a = await enroll(call, "a", KEY1);
    for (const candidates of [["host.example:1"], "1.2.3.4:5", Array(9).fill("1.2.3.4:5"), ["1.2.3.4"]]) {
      expect((await call("POST", "/api/v1/sync", { candidates }, a.deviceToken)).status).toBe(400);
    }
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
  test("lists everyone else; hub flag needs an endpoint", () => {
    const dev = (id: string, endpoint: string | null, hub = false): Device => ({
      id, name: id, publicKey: id, ip: id, endpoint, hub, candidates: ["1.1.1.1:1"],
      tokenHash: "", createdAt: 0, lastSeen: 0,
    });
    const peers = computePeers(dev("a", null), [dev("a", null), dev("h", "9.9.9.9:1", true), dev("x", null, true)]);
    expect(peers.map((p) => [p.name, p.hub, p.endpoints])).toEqual([
      ["h", true, ["9.9.9.9:1", "1.1.1.1:1"]],
      ["x", false, ["1.1.1.1:1"]],
    ]);
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
