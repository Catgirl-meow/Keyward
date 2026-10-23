import { ApiError, OfflineError } from "../core/api/client.ts";
import { fetchRevision, fullSync } from "../core/sync/sync.ts";
import { broadcast, type SyncStatus } from "../platform/messages.ts";
import { setUnlocked } from "../platform/session.ts";
import { session } from "../platform/storage.ts";
import { effectivePolicy, type EffectivePolicy, type RawPolicy } from "../core/vault/policy.ts";
import { clearPin } from "../platform/pin.ts";
import { loadPolicy, storePolicy } from "../platform/policy.ts";
import { loadSettings } from "../platform/settings.ts";
import { onLoggedOut, onSettingsChanged } from "./lock.ts";
import { unlockedCtx } from "./ctx.ts";

const inflight = new Map<string, Promise<SyncStatus>>();

let queue: Promise<unknown> = Promise.resolve();
/** A request that never answers mustn't hold up every later write: its turn ends after this. */
const TURN_MAX_MS = 120_000;
/** Full syncs and vault writes take turns. A sync replaces the stored vault with the server's
 * snapshot, so a write that landed between its fetch and its store would be lost locally (an
 * edit reverted, a new item gone until the next sync). Not reentrant: never nest. */
export function vaultTurn<T>(fn: () => Promise<T>): Promise<T> {
  const run = queue.then(fn, fn);
  queue = Promise.race([run.catch(() => {}), new Promise((r) => setTimeout(r, TURN_MAX_MS))]);
  return run;
}

/** Stores the account's policies when they changed and applies what can't wait for a read: no
 * PIN, the capped lock timeout. */
async function applyPolicies(accountId: string, eff: EffectivePolicy): Promise<void> {
  const before = await loadPolicy(accountId);
  if (JSON.stringify(before ?? { by: {} }) === JSON.stringify(eff)) return;
  await storePolicy(accountId, eff);
  if (eff.removePin) await clearPin(accountId);
  await onSettingsChanged(undefined, (await loadSettings()).lockTimeout);
  broadcast({ kind: "settings" });
}

export function syncAccount(accountId?: string, force = false): Promise<SyncStatus> {
  const key = accountId ?? "";
  let p = inflight.get(key);
  if (!p) {
    p = doSync(accountId, force).finally(() => inflight.delete(key));
    inflight.set(key, p);
  }
  return p;
}

/** A full sync that starts after everything already written: one in flight may predate it. */
export async function syncAfterWrite(accountId: string): Promise<SyncStatus> {
  await Promise.all([inflight.get(accountId), inflight.get("")].map((p) => p?.catch(() => {})));
  return syncAccount(accountId, true);
}

async function doSync(accountId: string | undefined, force: boolean): Promise<SyncStatus> {
  const c = await unlockedCtx(accountId);
  const id = c.account.id;
  let status: SyncStatus;
  try {
    if (!force) {
      const [rev, stored, last] = await Promise.all([fetchRevision(c.api), c.db.meta<number>("revision"), c.db.meta<number>("lastSync")]);
      if (rev != null && stored === rev && last) {
        status = { ok: true, at: Date.now() };
        await session.set(`sync:${id}`, status);
        return status;
      }
    }
    const before = [...c.ring.orgs.keys()].sort().join();
    const r = await vaultTurn(() => fullSync({ api: c.api, db: c.db, userKey: c.ring.user, cacheKey: c.cacheKey, orgKeys: new Map(c.ring.orgs) }));
    if ([...r.ring.orgs.keys()].sort().join() !== before) await setUnlocked(id, r.ring);
    await applyPolicies(id, effectivePolicy((await c.db.meta<RawPolicy[]>("policies")) ?? [], r.profile?.organizations ?? []));
    status = { ok: true, at: Date.now(), total: r.total, decrypted: r.decrypted };
    broadcast({ kind: "vault", accountId: id, full: true });
  } catch (e) {
    if (e instanceof ApiError && e.loggedOut) {
      await onLoggedOut(id);
      status = { ok: false, at: Date.now(), error: "Session expired — log in again" };
    } else {
      status = { ok: false, at: Date.now(), error: (e as Error).message, offline: e instanceof OfflineError };
    }
  }
  await session.set(`sync:${id}`, status);
  broadcast({ kind: "sync", accountId: id, status });
  return status;
}
