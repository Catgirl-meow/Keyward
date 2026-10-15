// Per-account IndexedDB. Raw server objects are stored exactly as received (still encrypted);
// the only decrypted data at rest lives in AES-GCM sealed "buckets" (see summaries.ts).
import type { RawCipher, RawCollection, RawFolder } from "../vault/types.ts";

const VERSION = 1;
const STORES = ["ciphers", "folders", "collections", "sends", "meta", "buckets", "outbox"] as const;
type StoreName = (typeof STORES)[number];

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((res, rej) => {
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}

function txDone(t: IDBTransaction): Promise<void> {
  return new Promise((res, rej) => {
    t.oncomplete = () => res();
    t.onerror = () => rej(t.error);
    t.onabort = () => rej(t.error ?? new Error("transaction aborted"));
  });
}

const cache = new Map<string, Promise<VaultDB>>();

export class VaultDB {
  readonly db: IDBDatabase;
  constructor(db: IDBDatabase) {
    this.db = db;
  }

  static open(accountId: string): Promise<VaultDB> {
    let p = cache.get(accountId);
    if (!p) {
      p = new Promise<VaultDB>((res, rej) => {
        const r = indexedDB.open(`kw-${accountId}`, VERSION);
        r.onupgradeneeded = () => {
          const db = r.result;
          for (const s of STORES) if (!db.objectStoreNames.contains(s)) db.createObjectStore(s, s === "meta" || s === "buckets" ? undefined : { keyPath: "id" });
        };
        r.onsuccess = () => {
          r.result.onversionchange = () => {
            r.result.close();
            cache.delete(accountId);
          };
          res(new VaultDB(r.result));
        };
        r.onerror = () => rej(r.error);
      });
      cache.set(accountId, p);
      p.catch(() => cache.delete(accountId));
    }
    return p;
  }

  static async destroy(accountId: string): Promise<void> {
    const p = cache.get(accountId);
    cache.delete(accountId);
    if (p) (await p.catch(() => null))?.db.close();
    await req(indexedDB.deleteDatabase(`kw-${accountId}`) as IDBRequest<any>).catch(() => {});
  }

  getAll<T = any>(store: StoreName): Promise<T[]> {
    return req(this.db.transaction(store).objectStore(store).getAll());
  }

  get<T = any>(store: StoreName, key: IDBValidKey): Promise<T | undefined> {
    return req(this.db.transaction(store).objectStore(store).get(key));
  }

  async put(store: StoreName, value: any, key?: IDBValidKey): Promise<void> {
    const t = this.db.transaction(store, "readwrite");
    t.objectStore(store).put(value, key);
    await txDone(t);
  }

  async delete(store: StoreName, key: IDBValidKey): Promise<void> {
    const t = this.db.transaction(store, "readwrite");
    t.objectStore(store).delete(key);
    await txDone(t);
  }

  /** Atomic multi-store write. `fn` must only enqueue requests (no awaits on foreign promises). */
  async write(stores: StoreName[], fn: (s: (n: StoreName) => IDBObjectStore) => void): Promise<void> {
    const t = this.db.transaction(stores, "readwrite");
    fn((n) => t.objectStore(n));
    await txDone(t);
  }

  getCipher(id: string): Promise<RawCipher | undefined> {
    return this.get<RawCipher>("ciphers", id);
  }
  getCiphers(): Promise<RawCipher[]> {
    return this.getAll<RawCipher>("ciphers");
  }
  getFolders(): Promise<RawFolder[]> {
    return this.getAll<RawFolder>("folders");
  }
  getCollections(): Promise<RawCollection[]> {
    return this.getAll<RawCollection>("collections");
  }
  meta<T = any>(key: string): Promise<T | undefined> {
    return this.get<T>("meta", key);
  }
  setMeta(key: string, value: any): Promise<void> {
    return this.put("meta", value, key);
  }

  /** All buckets as [index, sealedBlob]. */
  async buckets(): Promise<[number, Uint8Array][]> {
    const t = this.db.transaction("buckets");
    const s = t.objectStore("buckets");
    const [keys, vals] = await Promise.all([req(s.getAllKeys()), req(s.getAll())]);
    return keys.map((k, i) => [k as number, vals[i] as Uint8Array]);
  }
}
