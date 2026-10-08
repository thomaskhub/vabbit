// A small fake of the Cloudflare R2 bucket binding (get / put / delete / list with pages), for tests.
import type { R2BucketLike } from "../src/r2store.ts";

export class FakeR2 implements R2BucketLike {
  data = new Map<string, string>();
  puts = 0;
  constructor(public pageSize = 2) {}

  async get(key: string) {
    const v = this.data.get(key);
    return v === undefined ? null : { text: async () => v };
  }
  async put(key: string, value: string) {
    this.puts++;
    this.data.set(key, value);
  }
  async delete(key: string) {
    this.data.delete(key);
  }
  async list({ prefix, cursor }: { prefix: string; cursor?: string }) {
    const keys = [...this.data.keys()].filter((k) => k.startsWith(prefix)).sort();
    const start = cursor ? Number(cursor) : 0;
    const truncated = start + this.pageSize < keys.length;
    return {
      objects: keys.slice(start, start + this.pageSize).map((key) => ({ key })),
      truncated,
      cursor: truncated ? String(start + this.pageSize) : undefined,
    };
  }
}
