// Decrypted list data, sealed at rest. 32 buckets keyed by hash(id): a single-item edit
// re-seals ~1/32 of the list instead of the whole vault.
import { aesGcmDecrypt, aesGcmEncrypt, hkdf, importAesGcm } from "../crypto/primitives.ts";
import type { SymKey } from "../crypto/symkey.ts";
import { fromUtf8, utf8 } from "../util/bytes.ts";
import { fnv1a32 } from "../util/json.ts";
import type { Summary } from "../vault/types.ts";
import type { VaultDB } from "./db.ts";

export const BUCKETS = 32;
/** Bucket index holding folder / collection / org names. */
export const AUX_BUCKET = 1000;

export const bucketOf = (id: string) => fnv1a32(id) % BUCKETS;

export interface AuxData {
  folders: { id: string; name: string }[];
  collections: { id: string; orgId: string; name: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }[];
  orgs: { id: string; name: string; useTotp: boolean; type: number }[];
}

export async function cacheKey(userKey: SymKey): Promise<CryptoKey> {
  return importAesGcm(await hkdf(userKey.raw, "keyward", "keyward-cache-v1", 32));
}

export async function seal(key: CryptoKey, value: unknown): Promise<Uint8Array> {
  return aesGcmEncrypt(key, utf8(JSON.stringify(value)));
}

export async function unseal<T>(key: CryptoKey, blob: Uint8Array): Promise<T> {
  return JSON.parse(fromUtf8(await aesGcmDecrypt(key, blob)));
}

export interface Snapshot {
  items: Map<string, Summary>;
  aux: AuxData;
}

export async function loadSnapshot(db: VaultDB, key: CryptoKey): Promise<Snapshot> {
  const all = await db.buckets();
  const items = new Map<string, Summary>();
  let aux: AuxData = { folders: [], collections: [], orgs: [] };
  await Promise.all(
    all.map(async ([i, blob]) => {
      try {
        if (i === AUX_BUCKET) aux = await unseal<AuxData>(key, blob);
        else for (const s of await unseal<Summary[]>(key, blob)) items.set(s.id, s);
      } catch {
        // Wrong key (e.g. after key rotation) or corruption: treat as missing; next sync rebuilds it.
      }
    }),
  );
  return { items, aux };
}

/** Re-seals the given buckets from the full summary map (and optionally the aux bucket). */
export async function writeBuckets(db: VaultDB, key: CryptoKey, items: Map<string, Summary>, dirty: Iterable<number>, aux?: AuxData): Promise<void> {
  const groups = new Map<number, Summary[]>();
  const dirtySet = new Set(dirty);
  for (const i of dirtySet) groups.set(i, []);
  for (const s of items.values()) {
    const b = bucketOf(s.id);
    if (dirtySet.has(b)) groups.get(b)!.push(s);
  }
  const sealed: [number, Uint8Array][] = await Promise.all([...groups].map(async ([i, list]) => [i, await seal(key, list)] as [number, Uint8Array]));
  const sealedAux = aux ? await seal(key, aux) : null;
  await db.write(["buckets"], (s) => {
    const st = s("buckets");
    for (const [i, blob] of sealed) st.put(blob, i);
    if (sealedAux) st.put(sealedAux, AUX_BUCKET);
  });
}

export async function clearBuckets(db: VaultDB): Promise<void> {
  await db.write(["buckets"], (s) => s("buckets").clear());
}

/** Incremental update: touches only the buckets containing the changed ids. */
export async function patchBuckets(db: VaultDB, key: CryptoKey, upsert: Summary[], remove: string[] = []): Promise<void> {
  const byBucket = new Map<number, { up: Summary[]; rm: string[] }>();
  const slot = (i: number) => {
    let g = byBucket.get(i);
    if (!g) byBucket.set(i, (g = { up: [], rm: [] }));
    return g;
  };
  for (const s of upsert) slot(bucketOf(s.id)).up.push(s);
  for (const id of remove) slot(bucketOf(id)).rm.push(id);
  const sealed: [number, Uint8Array][] = [];
  for (const [i, g] of byBucket) {
    const blob = await db.get<Uint8Array>("buckets", i);
    let list: Summary[] = [];
    if (blob) list = await unseal<Summary[]>(key, blob).catch(() => []);
    const drop = new Set([...g.rm, ...g.up.map((s) => s.id)]);
    list = list.filter((s) => !drop.has(s.id)).concat(g.up);
    sealed.push([i, await seal(key, list)]);
  }
  await db.write(["buckets"], (s) => {
    for (const [i, blob] of sealed) s("buckets").put(blob, i);
  });
}

export async function writeAux(db: VaultDB, key: CryptoKey, aux: AuxData): Promise<void> {
  const blob = await seal(key, aux);
  await db.put("buckets", blob, AUX_BUCKET);
}
