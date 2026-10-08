import { describe, expect, test } from "bun:test";
import { MemoryStore, type Store } from "../src/store.ts";
import { R2Store } from "../src/r2store.ts";
import { FakeR2 } from "./fake-r2.ts";

const stores: Record<string, () => Store> = {
  memory: () => new MemoryStore(),
  r2: () => new R2Store(new FakeR2()),
};

for (const [name, make] of Object.entries(stores)) {
  describe(`${name} store`, () => {
    test("put and get round-trip JSON, a missing key is null", async () => {
      const s = make();
      expect(await s.get("devices/a.json")).toBeNull();
      await s.put("devices/a.json", { id: "a", n: [1, 2], nested: { ok: true } });
      expect(await s.get<unknown>("devices/a.json")).toEqual({ id: "a", n: [1, 2], nested: { ok: true } });
    });

    test("put overwrites", async () => {
      const s = make();
      await s.put("devices/a.json", { v: 1 });
      await s.put("devices/a.json", { v: 2 });
      expect(await s.get<unknown>("devices/a.json")).toEqual({ v: 2 });
    });

    test("delete removes, and deleting a missing key is fine", async () => {
      const s = make();
      await s.put("devices/a.json", { v: 1 });
      await s.delete("devices/a.json");
      expect(await s.get("devices/a.json")).toBeNull();
      await s.delete("devices/a.json");
    });

    test("list returns the names under one prefix only", async () => {
      const s = make();
      await s.put("devices/a.json", {});
      await s.put("devices/b.json", {});
      await s.put("setup-keys/c.json", {});
      expect((await s.list("devices/")).sort()).toEqual(["a.json", "b.json"]);
      expect(await s.list("setup-keys/")).toEqual(["c.json"]);
      expect(await s.list("nothing/")).toEqual([]);
    });

    test("list sees every object when there are many (several pages)", async () => {
      const s = make();
      const want: string[] = [];
      for (let i = 0; i < 7; i++) {
        await s.put(`devices/d${i}.json`, { i });
        want.push(`d${i}.json`);
      }
      expect((await s.list("devices/")).sort()).toEqual(want);
    });

    test("invalid keys and prefixes are rejected before any storage access", async () => {
      const s = make();
      for (const bad of ["a.json", "devices/a.txt", "devices/../x.json", "devices/a/b.json", "Devices/a.json", "devices/.json", ""]) {
        await expect(s.get(bad)).rejects.toThrow();
        await expect(s.put(bad, {})).rejects.toThrow();
        await expect(s.delete(bad)).rejects.toThrow();
      }
      for (const bad of ["devices", "devices//", "../", "", "a/b/"]) {
        await expect(s.list(bad)).rejects.toThrow();
      }
    });
  });
}

describe("r2 store specifics", () => {
  test("uses the bucket as given: keys are stored under their full name", async () => {
    const r2 = new FakeR2();
    await new R2Store(r2).put("setup-keys/abc.json", { x: 1 });
    expect([...r2.data.keys()]).toEqual(["setup-keys/abc.json"]);
    expect(r2.data.get("setup-keys/abc.json")).toBe('{"x":1}');
  });
});
