// Key/value storage for JSON records. Bunny Storage in production, memory in tests.

export interface Store {
  get<T>(key: string): Promise<T | null>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
  /** Lists object names (not full keys) directly under a prefix ending in "/". */
  list(prefix: string): Promise<string[]>;
}

const KEY_RE = /^[a-z-]+\/[A-Za-z0-9_-]+\.json$/;
const PREFIX_RE = /^[a-z-]+\/$/;

function checkKey(key: string): void {
  if (!KEY_RE.test(key)) throw new Error(`invalid storage key: ${key}`);
}

export class MemoryStore implements Store {
  private data = new Map<string, string>();

  async get<T>(key: string): Promise<T | null> {
    checkKey(key);
    const v = this.data.get(key);
    return v === undefined ? null : (JSON.parse(v) as T);
  }

  async put(key: string, value: unknown): Promise<void> {
    checkKey(key);
    this.data.set(key, JSON.stringify(value));
  }

  async delete(key: string): Promise<void> {
    checkKey(key);
    this.data.delete(key);
  }

  async list(prefix: string): Promise<string[]> {
    if (!PREFIX_RE.test(prefix)) throw new Error(`invalid prefix: ${prefix}`);
    return [...this.data.keys()]
      .filter((k) => k.startsWith(prefix))
      .map((k) => k.slice(prefix.length));
  }
}

export interface BunnyStorageOptions {
  zone: string;
  accessKey: string;
  /** Region endpoint, e.g. "storage.bunnycdn.com" or "ny.storage.bunnycdn.com". */
  host?: string;
  fetch?: typeof fetch;
}

/** Bunny Storage HTTP API: https://docs.bunny.net/reference/storage-api */
export class BunnyStorage implements Store {
  private base: string;
  private accessKey: string;
  private fetch: typeof fetch;

  constructor(opts: BunnyStorageOptions) {
    if (!/^[a-z0-9-]+$/i.test(opts.zone)) throw new Error("invalid storage zone name");
    const host = opts.host ?? "storage.bunnycdn.com";
    if (!/^[a-z0-9.-]+$/i.test(host)) throw new Error("invalid storage host");
    this.base = `https://${host}/${opts.zone}/`;
    this.accessKey = opts.accessKey;
    this.fetch = opts.fetch ?? fetch;
  }

  private req(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("AccessKey", this.accessKey);
    return this.fetch(this.base + path, { ...init, headers });
  }

  async get<T>(key: string): Promise<T | null> {
    checkKey(key);
    const res = await this.req(key);
    if (res.status === 404) {
      await res.body?.cancel();
      return null;
    }
    if (!res.ok) throw new Error(`storage get ${res.status}`);
    return (await res.json()) as T;
  }

  async put(key: string, value: unknown): Promise<void> {
    checkKey(key);
    const res = await this.req(key, {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream" },
      body: JSON.stringify(value),
    });
    await res.body?.cancel();
    if (!res.ok) throw new Error(`storage put ${res.status}`);
  }

  async delete(key: string): Promise<void> {
    checkKey(key);
    const res = await this.req(key, { method: "DELETE" });
    await res.body?.cancel();
    if (!res.ok && res.status !== 404) throw new Error(`storage delete ${res.status}`);
  }

  async list(prefix: string): Promise<string[]> {
    if (!PREFIX_RE.test(prefix)) throw new Error(`invalid prefix: ${prefix}`);
    const res = await this.req(prefix, { headers: { Accept: "application/json" } });
    if (res.status === 404) {
      await res.body?.cancel();
      return [];
    }
    if (!res.ok) throw new Error(`storage list ${res.status}`);
    const items = (await res.json()) as { ObjectName: string; IsDirectory: boolean }[];
    return items.filter((i) => !i.IsDirectory).map((i) => i.ObjectName);
  }
}
