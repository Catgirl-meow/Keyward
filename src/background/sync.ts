import { ApiError, OfflineError } from "../core/api/client.ts";
import { fetchRevision, fullSync } from "../core/sync/sync.ts";
import { broadcast, type SyncStatus } from "../platform/messages.ts";
import { setUnlocked } from "../platform/session.ts";
import { session } from "../platform/storage.ts";
import { onLoggedOut } from "./lock.ts";
import { unlockedCtx } from "./ctx.ts";

const inflight = new Map<string, Promise<SyncStatus>>();

export function syncAccount(accountId?: string, force = false): Promise<SyncStatus> {
  const key = accountId ?? "";
  let p = inflight.get(key);
  if (!p) {
    p = doSync(accountId, force).finally(() => inflight.delete(key));
    inflight.set(key, p);
  }
  return p;
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
    const r = await fullSync({ api: c.api, db: c.db, userKey: c.ring.user, cacheKey: c.cacheKey, orgKeys: new Map(c.ring.orgs) });
    if ([...r.ring.orgs.keys()].sort().join() !== before) await setUnlocked(id, r.ring);
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
