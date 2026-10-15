// Full sync with incremental decryption: only items whose revisionDate changed (or that
// previously failed to decrypt) are decrypted again. Everything else keeps its sealed summary.
import type { Api } from "../api/client.ts";
import { decryptString } from "../crypto/encstring.ts";
import { decryptOrgKey, decryptPrivateKey, type PrivateKeyPair } from "../crypto/keys.ts";
import type { SymKey } from "../crypto/symkey.ts";
import type { VaultDB } from "../store/db.ts";
import { bucketOf, loadSnapshot, writeBuckets, type AuxData } from "../store/summaries.ts";
import { decryptCipher, summarize, type KeyRing } from "../vault/cipher.ts";
import type { RawCipher, RawCollection, RawFolder, RawOrg } from "../vault/types.ts";

export interface SyncDeps {
  api: Api;
  db: VaultDB;
  userKey: SymKey;
  cacheKey: CryptoKey;
  /** Known org keys; missing ones are derived (RSA) and added in place. */
  orgKeys: Map<string, SymKey>;
}

export interface SyncResult {
  ring: KeyRing;
  total: number;
  decrypted: number;
  removed: number;
  revision: number | null;
  profile: any;
}

export async function deriveOrgKeys(profile: any, userKey: SymKey, known: Map<string, SymKey>): Promise<Map<string, SymKey>> {
  const orgs: RawOrg[] = profile?.organizations ?? [];
  const out = new Map<string, SymKey>();
  let priv: PrivateKeyPair | null = null;
  for (const o of orgs) {
    if (!o.key || o.enabled === false) continue;
    const have = known.get(o.id);
    if (have) {
      out.set(o.id, have);
      continue;
    }
    const encPriv = profile.privateKey ?? profile.accountKeys?.publicKeyEncryptionKeyPair?.wrappedPrivateKey;
    if (!encPriv) continue;
    try {
      priv ??= await decryptPrivateKey(encPriv, userKey);
      out.set(o.id, await decryptOrgKey(o.key, priv));
    } catch {
      // Org key unusable (e.g. not yet confirmed): its items will show as unreadable until it is.
    }
  }
  return out;
}

export async function fetchRevision(api: Api): Promise<number | null> {
  try {
    const r = await api.get("/accounts/revision-date");
    const n = Number(r);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

export async function fullSync(d: SyncDeps): Promise<SyncResult> {
  const revision = await fetchRevision(d.api);
  const data = await d.api.get("/sync?excludeDomains=false");
  const profile = data.profile ?? {};

  const orgKeys = await deriveOrgKeys(profile, d.userKey, d.orgKeys);
  d.orgKeys.clear();
  for (const [k, v] of orgKeys) d.orgKeys.set(k, v);
  const ring: KeyRing = { user: d.userKey, orgs: orgKeys };

  const [prev, snap] = await Promise.all([d.db.getCiphers(), loadSnapshot(d.db, d.cacheKey)]);
  const prevRev = new Map(prev.map((c) => [c.id, c.revisionDate]));
  const items = snap.items;
  const dirty = new Set<number>();
  const ciphers: RawCipher[] = (data.ciphers ?? []).filter((c: RawCipher) => c && typeof c.id === "string");
  const seen = new Set<string>();
  let decrypted = 0;

  await Promise.all(
    ciphers.map(async (c) => {
      seen.add(c.id);
      const old = items.get(c.id);
      if (old && !old.err && prevRev.get(c.id) === c.revisionDate) return;
      const view = await decryptCipher(c, ring);
      items.set(c.id, summarize(view));
      dirty.add(bucketOf(c.id));
      decrypted++;
    }),
  );
  let removed = 0;
  for (const id of [...items.keys()]) {
    if (!seen.has(id)) {
      items.delete(id);
      dirty.add(bucketOf(id));
      removed++;
    }
  }

  const folders: RawFolder[] = data.folders ?? [];
  const collections: RawCollection[] = data.collections ?? [];
  const aux: AuxData = {
    folders: (
      await Promise.all(folders.map(async (f) => ({ id: f.id, name: await decryptString(f.name, d.userKey).catch(() => "⚠ Folder") })))
    ).sort((a, b) => a.name.localeCompare(b.name)),
    collections: (
      await Promise.all(
        collections.map(async (c) => {
          const k = orgKeys.get(c.organizationId);
          return {
            id: c.id,
            orgId: c.organizationId,
            name: k ? await decryptString(c.name, k).catch(() => "⚠ Collection") : "⚠ Collection",
            readOnly: !!c.readOnly,
            hidePasswords: !!c.hidePasswords,
            manage: !!c.manage,
          };
        }),
      )
    ).sort((a, b) => a.name.localeCompare(b.name)),
    orgs: ((profile.organizations ?? []) as RawOrg[]).map((o) => ({ id: o.id, name: o.name, useTotp: o.useTotp !== false, type: o.type ?? 2 })),
  };

  await d.db.write(["ciphers", "folders", "collections", "sends", "meta"], (s) => {
    const cs = s("ciphers");
    cs.clear();
    for (const c of ciphers) cs.put(c);
    const fs = s("folders");
    fs.clear();
    for (const f of folders) fs.put(f);
    const cols = s("collections");
    cols.clear();
    for (const c of collections) cols.put(c);
    const ss = s("sends");
    ss.clear();
    for (const x of data.sends ?? []) if (x?.id) ss.put(x);
    const m = s("meta");
    m.put(profile, "profile");
    m.put(data.policies ?? [], "policies");
    m.put(equivalentDomains(data.domains), "domains");
    m.put(Date.now(), "lastSync");
    if (revision != null) m.put(revision, "revision");
  });
  await writeBuckets(d.db, d.cacheKey, items, dirty, aux);
  return { ring, total: ciphers.length, decrypted, removed, revision, profile };
}

/** Flattens custom + non-excluded global equivalent-domain groups. */
export function equivalentDomains(domains: any): string[][] {
  if (!domains) return [];
  const out: string[][] = [];
  for (const g of domains.equivalentDomains ?? []) if (Array.isArray(g) && g.length > 1) out.push(g.map((x: string) => x.toLowerCase()));
  for (const g of domains.globalEquivalentDomains ?? []) if (g && !g.excluded && Array.isArray(g.domains)) out.push(g.domains.map((x: string) => x.toLowerCase()));
  return out;
}
