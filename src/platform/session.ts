// Unlocked key material lives only in chrome.storage.session (RAM, trusted contexts only),
// except when the user opts into "never lock" / PIN-survives-restart.
import { SymKey } from "../core/crypto/symkey.ts";
import type { KeyRing } from "../core/vault/cipher.ts";
import { cacheKey } from "../core/store/summaries.ts";
import { local, session } from "./storage.ts";

interface Unlocked {
  userKey: string;
  orgKeys: Record<string, string>;
  at: number;
}

const ringCache = new Map<string, { raw: string; ring: KeyRing; cache: Promise<CryptoKey> }>();

export async function getRing(accountId: string): Promise<KeyRing | null> {
  const u = await session.get<Unlocked>(`unlocked:${accountId}`);
  if (!u) {
    ringCache.delete(accountId);
    return null;
  }
  const sig = u.userKey + JSON.stringify(u.orgKeys);
  const hit = ringCache.get(accountId);
  if (hit && hit.raw === sig) return hit.ring;
  const user = SymKey.fromB64(u.userKey);
  const ring: KeyRing = { user, orgs: new Map(Object.entries(u.orgKeys).map(([k, v]) => [k, SymKey.fromB64(v)])) };
  ringCache.set(accountId, { raw: sig, ring, cache: cacheKey(user) });
  return ring;
}

export async function getCacheKey(accountId: string): Promise<CryptoKey | null> {
  const ring = await getRing(accountId);
  if (!ring) return null;
  return ringCache.get(accountId)!.cache;
}

export async function setUnlocked(accountId: string, ring: KeyRing): Promise<void> {
  const u: Unlocked = {
    userKey: ring.user.toB64(),
    orgKeys: Object.fromEntries([...ring.orgs].map(([k, v]) => [k, v.toB64()])),
    at: Date.now(),
  };
  await session.set(`unlocked:${accountId}`, u);
}

export async function clearUnlocked(accountId: string): Promise<void> {
  ringCache.delete(accountId);
  // With the keys go the popup's kept screen and unsaved forms (ui/data/resume.ts).
  await session.remove([`unlocked:${accountId}`, `ui:${accountId}`]);
  await local.remove(`persistKey:${accountId}`);
}

export async function isUnlocked(accountId: string): Promise<boolean> {
  return !!(await session.get(`unlocked:${accountId}`));
}

/** "Never lock": keep the user key on disk so a browser restart does not lock. */
export async function persistUserKey(accountId: string, ring: KeyRing | null): Promise<void> {
  if (ring) await local.set(`persistKey:${accountId}`, ring.user.toB64());
  else await local.remove(`persistKey:${accountId}`);
}

export async function restorePersisted(accountId: string): Promise<KeyRing | null> {
  const k = await local.get<string>(`persistKey:${accountId}`);
  if (!k) return null;
  const ring: KeyRing = { user: SymKey.fromB64(k), orgs: new Map() };
  await setUnlocked(accountId, ring);
  return ring;
}
