// The EdgeGuard control plane API. Pure request -> response; storage is injected.

import { isWireGuardKey, randomId, randomToken, sha256Hex, timingSafeEqual } from "./crypto.ts";
import { allocate, type Cidr, parseCidr } from "./ipam.ts";
import type { Store } from "./store.ts";

export interface Config {
  /** Hex SHA-256 of the admin token. */
  adminTokenSha256: string;
  networkCidr: string;
  networkName: string;
  /** Override for tests. */
  now?: () => number;
}

export interface Device {
  id: string;
  name: string;
  publicKey: string;
  ip: string;
  endpoint: string | null;
  /** NAT traversal candidates the device reported: STUN-mapped and LAN addresses. */
  candidates?: string[];
  /** TLS-over-TCP relay a hub offers to devices on networks that block UDP. */
  relay?: Relay | null;
  hub: boolean;
  tokenHash: string;
  createdAt: number;
  lastSeen: number;
  /** When the device loses access (ms epoch); null or absent = never. */
  expiresAt?: number | null;
}

export interface SetupKey {
  id: string;
  hash: string;
  reusable: boolean;
  maxUses: number; // 0 = unlimited (reusable keys only)
  uses: number;
  expiresAt: number | null; // null = never
  /** Devices enrolled with this key lose access this long after joining. */
  deviceTtlSeconds?: number | null;
  createdAt: number;
}

export interface Relay {
  addr: string;
  /** Hex SHA-256 of the relay's self-signed certificate, pinned by clients. */
  fingerprint: string;
}

export interface Peer {
  name: string;
  publicKey: string;
  ip: string;
  hub: boolean;
  /** Addresses to try, best first: static endpoint, then reported candidates. */
  endpoints: string[];
  relay?: Relay;
}

const MAX_BODY = 8 * 1024;
const LAST_SEEN_WRITE_MS = 5 * 60 * 1000;
const MAX_CANDIDATES = 8;
const DEFAULT_KEY_TTL = 24 * 3600;
const MAX_KEY_TTL = 10 * 365 * 24 * 3600;
const MAX_DEVICE_TTL = 10 * 365 * 24 * 3600;

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Strict-Transport-Security": "max-age=31536000",
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: SECURITY_HEADERS });
}

export function createHandler(store: Store, cfg: Config): (req: Request) => Promise<Response> {
  if (!/^[0-9a-f]{64}$/.test(cfg.adminTokenSha256)) {
    throw new Error("ADMIN_TOKEN_SHA256 must be 64 lowercase hex characters");
  }
  const cidr = parseCidr(cfg.networkCidr);
  const now = cfg.now ?? Date.now;
  const api = new Api(store, cfg, cidr, now);

  return async (req: Request): Promise<Response> => {
    try {
      return await api.route(req);
    } catch (e) {
      if (e instanceof HttpError) return json(e.status, { error: e.message });
      console.error("internal error:", e);
      return json(500, { error: "internal error" });
    }
  };
}

class Api {
  constructor(
    private store: Store,
    private cfg: Config,
    private cidr: Cidr,
    private now: () => number,
  ) {}

  async route(req: Request): Promise<Response> {
    const path = new URL(req.url).pathname.replace(/\/+$/, "") || "/";
    const m = req.method;
    let match: RegExpExecArray | null;

    if (path === "/healthz" && m === "GET") return json(200, { ok: true });

    if (path === "/api/v1/enroll" && m === "POST") return this.enroll(req);
    if (path === "/api/v1/sync" && m === "POST") return this.sync(req);
    if (path === "/api/v1/device" && m === "DELETE") {
      const self = await this.requireDevice(req);
      return this.deleteDevice(self.id);
    }

    if (path === "/api/v1/network" && m === "GET") {
      await this.requireAdmin(req);
      return json(200, { name: this.cfg.networkName, cidr: this.cidr.text });
    }
    if (path === "/api/v1/setup-keys") {
      await this.requireAdmin(req);
      if (m === "POST") return this.createSetupKey(req);
      if (m === "GET") return this.listSetupKeys();
    }
    if ((match = /^\/api\/v1\/setup-keys\/([0-9a-f]{16})$/.exec(path)) && m === "DELETE") {
      await this.requireAdmin(req);
      return this.deleteSetupKey(match[1]);
    }
    if (path === "/api/v1/devices" && m === "GET") {
      await this.requireAdmin(req);
      const devices = await this.allDevices();
      return json(200, { devices: devices.map(publicDevice) });
    }
    if ((match = /^\/api\/v1\/devices\/([0-9a-f]{16})$/.exec(path))) {
      await this.requireAdmin(req);
      if (m === "DELETE") return this.deleteDevice(match[1]);
      if (m === "PATCH") return this.patchDevice(match[1], req);
    }
    throw new HttpError(404, "not found");
  }

  // ---- auth ----------------------------------------------------------------

  private bearer(req: Request): string {
    const h = req.headers.get("Authorization") ?? "";
    const m = /^Bearer ([A-Za-z0-9_.-]{1,200})$/.exec(h);
    if (!m) throw new HttpError(401, "unauthorized");
    return m[1];
  }

  private async requireAdmin(req: Request): Promise<void> {
    const token = this.bearer(req);
    const hash = await sha256Hex(token);
    if (!token.startsWith("ega_") || !timingSafeEqual(hash, this.cfg.adminTokenSha256)) {
      throw new HttpError(401, "unauthorized");
    }
  }

  private async requireDevice(req: Request): Promise<Device> {
    const token = this.bearer(req);
    const m = /^egd_([0-9a-f]{16})\.[A-Za-z0-9_-]{43}$/.exec(token);
    if (!m) throw new HttpError(401, "unauthorized");
    const [dev, hash] = await Promise.all([
      this.store.get<Device>(`devices/${m[1]}.json`),
      sha256Hex(token),
    ]);
    if (!dev || !timingSafeEqual(hash, dev.tokenHash)) throw new HttpError(401, "unauthorized");
    if (expired(dev, this.now())) {
      // Clean up so it also disappears from the admin's list.
      await this.store.delete(`devices/${dev.id}.json`);
      throw new HttpError(401, "device access expired");
    }
    return dev;
  }

  // ---- setup keys ------------------------------------------------------------

  private async createSetupKey(req: Request): Promise<Response> {
    const body = await readJson(req);
    const reusable = optBool(body.reusable, "reusable") ?? false;
    // ttlSeconds 0 = the key never expires (revoke it with DELETE when done).
    const ttl = body.ttlSeconds === 0 ? 0 : (optInt(body.ttlSeconds, "ttlSeconds", 60, MAX_KEY_TTL) ?? DEFAULT_KEY_TTL);
    const deviceTtl = optInt(body.deviceTtlSeconds, "deviceTtlSeconds", 60, MAX_DEVICE_TTL) ?? null;
    const maxUses = optInt(body.maxUses, "maxUses", 0, 100000) ?? (reusable ? 0 : 1);
    if (!reusable && maxUses !== 1) throw new HttpError(400, "one-time keys have maxUses 1");

    const key = randomToken("egk_");
    const hash = await sha256Hex(key);
    const t = this.now();
    const rec: SetupKey = {
      id: hash.slice(0, 16),
      hash,
      reusable,
      maxUses,
      uses: 0,
      expiresAt: ttl === 0 ? null : t + ttl * 1000,
      deviceTtlSeconds: deviceTtl,
      createdAt: t,
    };
    await this.store.put(`setup-keys/${hash}.json`, rec);
    return json(201, { key, ...publicKey(rec) });
  }

  private async listSetupKeys(): Promise<Response> {
    const names = await this.store.list("setup-keys/");
    const recs = await Promise.all(names.map((n) => this.store.get<SetupKey>(`setup-keys/${n}`)));
    const keys = recs.filter((r): r is SetupKey => r !== null).map(publicKey);
    return json(200, { setupKeys: keys });
  }

  private async deleteSetupKey(id: string): Promise<Response> {
    const names = await this.store.list("setup-keys/");
    const name = names.find((n) => n.startsWith(id));
    if (!name) throw new HttpError(404, "setup key not found");
    await this.store.delete(`setup-keys/${name}`);
    return json(200, { deleted: id });
  }

  /** Validates a setup key and consumes one use. */
  private async consumeSetupKey(key: unknown): Promise<SetupKey> {
    if (typeof key !== "string" || !/^egk_[A-Za-z0-9_-]{43}$/.test(key)) {
      throw new HttpError(401, "invalid setup key");
    }
    const hash = await sha256Hex(key);
    const storeKey = `setup-keys/${hash}.json`;
    const rec = await this.store.get<SetupKey>(storeKey);
    if (!rec || !timingSafeEqual(rec.hash, hash)) throw new HttpError(401, "invalid setup key");
    if (rec.expiresAt !== null && rec.expiresAt <= this.now()) throw new HttpError(401, "setup key expired");
    if (rec.maxUses !== 0 && rec.uses >= rec.maxUses) throw new HttpError(401, "setup key used up");
    rec.uses++;
    if (!rec.reusable && rec.uses >= rec.maxUses) await this.store.delete(storeKey);
    else await this.store.put(storeKey, rec);
    return rec;
  }

  // ---- devices ---------------------------------------------------------------

  private async allDevices(): Promise<Device[]> {
    const names = await this.store.list("devices/");
    const recs = await Promise.all(names.map((n) => this.store.get<Device>(`devices/${n}`)));
    return recs.filter((r): r is Device => r !== null).sort((a, b) => a.createdAt - b.createdAt);
  }

  private async enroll(req: Request): Promise<Response> {
    const body = await readJson(req);
    const name = reqName(body.name);
    const publicKey = body.publicKey;
    if (!isWireGuardKey(publicKey)) throw new HttpError(400, "publicKey must be a base64 WireGuard key");
    const endpoint = optEndpoint(body.endpoint);
    // Hubs see other devices' traffic in the clear, so only the admin can make
    // one (PATCH /devices/:id). A device can never promote itself.
    if (body.hub !== undefined) throw new HttpError(400, "hub can only be set by the admin");

    // Validate everything before consuming the key.
    const setupKey = await this.consumeSetupKey(body.setupKey);

    const devices = await this.allDevices();
    if (devices.some((d) => d.publicKey === publicKey)) {
      throw new HttpError(409, "a device with this public key already exists");
    }
    const ip = allocate(this.cidr, new Set(devices.map((d) => d.ip)), await sha256Hex(publicKey));
    if (!ip) throw new HttpError(507, "network is full");

    const id = randomId();
    const token = `egd_${id}.${randomToken("", 32)}`;
    const t = this.now();
    const dev: Device = {
      id,
      name,
      publicKey,
      ip,
      endpoint,
      hub: false,
      tokenHash: await sha256Hex(token),
      createdAt: t,
      lastSeen: t,
      expiresAt: setupKey.deviceTtlSeconds ? t + setupKey.deviceTtlSeconds * 1000 : null,
    };
    await this.store.put(`devices/${id}.json`, dev);
    return json(201, {
      device: publicDevice(dev),
      deviceToken: token,
      network: { name: this.cfg.networkName, cidr: this.cidr.text },
    });
  }

  private async deleteDevice(id: string): Promise<Response> {
    const dev = await this.store.get<Device>(`devices/${id}.json`);
    if (!dev) throw new HttpError(404, "device not found");
    await this.store.delete(`devices/${id}.json`);
    return json(200, { deleted: id });
  }

  private async patchDevice(id: string, req: Request): Promise<Response> {
    const body = await readJson(req);
    const key = `devices/${id}.json`;
    const dev = await this.store.get<Device>(key);
    if (!dev) throw new HttpError(404, "device not found");
    if (body.name !== undefined) dev.name = reqName(body.name);
    const hub = optBool(body.hub, "hub");
    if (hub !== undefined) {
      if (hub && !dev.endpoint) throw new HttpError(400, "a hub needs a public endpoint");
      dev.hub = hub;
    }
    // expiresInSeconds: a number sets a new end date from now, null removes it.
    if (body.expiresInSeconds === null) dev.expiresAt = null;
    else if (body.expiresInSeconds !== undefined) {
      dev.expiresAt = this.now() + optInt(body.expiresInSeconds, "expiresInSeconds", 60, MAX_DEVICE_TTL)! * 1000;
    }
    await this.store.put(key, dev);
    return json(200, { device: publicDevice(dev) });
  }

  private async sync(req: Request): Promise<Response> {
    const self = await this.requireDevice(req);
    const body = await readJson(req);
    const endpoint = optEndpoint(body.endpoint);
    // Omitted candidates (status checks, one-off calls) keep the stored ones.
    const candidates = body.candidates === undefined ? (self.candidates ?? []) : optCandidates(body.candidates);
    const relay = body.relay === undefined ? (self.relay ?? null) : optRelay(body.relay);
    const t = this.now();
    if (
      endpoint !== self.endpoint ||
      candidates.join() !== (self.candidates ?? []).join() ||
      JSON.stringify(relay) !== JSON.stringify(self.relay ?? null) ||
      t - self.lastSeen > LAST_SEEN_WRITE_MS
    ) {
      self.endpoint = endpoint;
      self.candidates = candidates;
      self.relay = relay;
      // Losing the endpoint means peers can no longer dial it as a hub.
      if (!endpoint) self.hub = false;
      self.lastSeen = t;
      await this.store.put(`devices/${self.id}.json`, self);
    }

    const devices = await this.allDevices();
    return json(200, {
      self: publicDevice(self),
      network: { name: this.cfg.networkName, cidr: this.cidr.text },
      address: `${self.ip}/${this.cidr.bits}`,
      peers: computePeers(self, devices.filter((d) => !expired(d, t))),
    });
  }
}

/**
 * Every other device is a peer. The client decides per peer whether traffic
 * goes direct (after a successful hole punch) or via the hub.
 */
export function computePeers(self: Device, devices: Device[]): Peer[] {
  return devices
    .filter((d) => d.id !== self.id)
    .map((d) => ({
      name: d.name,
      publicKey: d.publicKey,
      ip: d.ip,
      hub: d.hub && d.endpoint !== null,
      endpoints: [...(d.endpoint ? [d.endpoint] : []), ...(d.candidates ?? [])].filter(
        (e, i, all) => all.indexOf(e) === i,
      ),
      // Only an admin-promoted hub's relay is ever handed out.
      ...(d.hub && d.endpoint !== null && d.relay ? { relay: d.relay } : {}),
    }));
}

function expired(d: Device, now: number): boolean {
  return d.expiresAt != null && d.expiresAt <= now;
}

function iso(ms: number | null | undefined): string | null {
  return ms == null ? null : new Date(ms).toISOString();
}

function publicDevice(d: Device) {
  return {
    id: d.id,
    name: d.name,
    publicKey: d.publicKey,
    ip: d.ip,
    endpoint: d.endpoint,
    candidates: d.candidates ?? [],
    hub: d.hub,
    createdAt: new Date(d.createdAt).toISOString(),
    lastSeen: new Date(d.lastSeen).toISOString(),
    expiresAt: iso(d.expiresAt),
  };
}

function publicKey(k: SetupKey) {
  return {
    id: k.id,
    reusable: k.reusable,
    maxUses: k.maxUses,
    uses: k.uses,
    expiresAt: iso(k.expiresAt),
    deviceTtlSeconds: k.deviceTtlSeconds ?? null,
    createdAt: new Date(k.createdAt).toISOString(),
  };
}

// ---- input validation --------------------------------------------------------

async function readJson(req: Request): Promise<Record<string, unknown>> {
  const len = Number(req.headers.get("Content-Length") ?? "0");
  if (len > MAX_BODY) throw new HttpError(413, "body too large");
  if (!req.body) return {};
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY) {
      await reader.cancel();
      throw new HttpError(413, "body too large");
    }
    chunks.push(value);
  }
  if (size === 0) return {};
  const buf = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buf));
  } catch {
    throw new HttpError(400, "invalid JSON");
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new HttpError(400, "expected a JSON object");
  return v as Record<string, unknown>;
}

function reqName(v: unknown): string {
  if (typeof v !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(v)) {
    throw new HttpError(400, "name must be 1-63 chars of letters, digits, '.', '_' or '-'");
  }
  return v;
}

function optBool(v: unknown, field: string): boolean | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "boolean") throw new HttpError(400, `${field} must be a boolean`);
  return v;
}

function optInt(v: unknown, field: string, min: number, max: number): number | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
    throw new HttpError(400, `${field} must be an integer between ${min} and ${max}`);
  }
  return v;
}

function optRelay(v: unknown): Relay | null {
  if (v === null) return null;
  if (typeof v !== "object" || Array.isArray(v)) throw new HttpError(400, "relay must be an object");
  const r = v as Record<string, unknown>;
  const addr = optEndpoint(r.addr);
  if (!addr) throw new HttpError(400, "relay.addr must be host:port");
  if (typeof r.fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(r.fingerprint)) {
    throw new HttpError(400, "relay.fingerprint must be 64 hex characters");
  }
  return { addr, fingerprint: r.fingerprint };
}

/** Candidates must be literal IP:port (no DNS names), deduplicated, at most 8. */
function optCandidates(v: unknown): string[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v) || v.length > MAX_CANDIDATES) {
    throw new HttpError(400, `candidates must be an array of at most ${MAX_CANDIDATES} addresses`);
  }
  const out: string[] = [];
  for (const c of v) {
    const ep = optEndpoint(c);
    if (!ep || !/^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-fA-F:.]+\]):\d+$/.test(ep)) {
      throw new HttpError(400, "candidates must be IP:port");
    }
    if (!out.includes(ep)) out.push(ep);
  }
  return out;
}

/** Accepts "host:port" with an IPv4 address, "[IPv6]" or a DNS name. */
export function optEndpoint(v: unknown): string | null {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v !== "string" || v.length > 260) throw new HttpError(400, "invalid endpoint");
  const m = /^(\[[0-9a-fA-F:.]{2,45}\]|[A-Za-z0-9.-]{1,253}):(\d{1,5})$/.exec(v);
  if (!m) throw new HttpError(400, "endpoint must be host:port");
  const port = Number(m[2]);
  if (port < 1 || port > 65535) throw new HttpError(400, "endpoint port out of range");
  const host = m[1];
  if (!host.startsWith("[")) {
    if (/^[\d.]+$/.test(host)) {
      const parts = host.split(".");
      if (parts.length !== 4 || parts.some((p) => p === "" || Number(p) > 255)) {
        throw new HttpError(400, "invalid endpoint IPv4 address");
      }
    } else if (host.split(".").some((l) => l === "" || l.length > 63 || l.startsWith("-") || l.endsWith("-"))) {
      throw new HttpError(400, "invalid endpoint hostname");
    }
  }
  return v;
}
