// The Store on a Cloudflare R2 bucket binding, for running the control plane as a Cloudflare Worker.
// Only the four binding methods below are used, so no Cloudflare types package is needed.

import { checkKey, checkPrefix, type Store } from "./store.ts";

/** The part of an R2 bucket binding that Vabbit uses. */
export interface R2BucketLike {
  get(key: string): Promise<{ text(): Promise<string> } | null>;
  put(key: string, value: string): Promise<unknown>;
  delete(key: string): Promise<unknown>;
  list(options: { prefix: string; cursor?: string }): Promise<{
    objects: { key: string }[];
    truncated: boolean;
    cursor?: string;
  }>;
}

export class R2Store implements Store {
  constructor(private bucket: R2BucketLike) {}

  async get<T>(key: string): Promise<T | null> {
    checkKey(key);
    const obj = await this.bucket.get(key);
    return obj ? (JSON.parse(await obj.text()) as T) : null;
  }

  async put(key: string, value: unknown): Promise<void> {
    checkKey(key);
    await this.bucket.put(key, JSON.stringify(value));
  }

  async delete(key: string): Promise<void> {
    checkKey(key);
    await this.bucket.delete(key);
  }

  async list(prefix: string): Promise<string[]> {
    checkPrefix(prefix);
    const names: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.bucket.list({ prefix, cursor });
      for (const o of page.objects) names.push(o.key.slice(prefix.length));
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor);
    return names;
  }
}
