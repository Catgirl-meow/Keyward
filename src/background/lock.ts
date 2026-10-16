// Lock / logout / timeouts. No polling: a single alarm per account carries the deadline.
import { VaultDB } from "../core/store/db.ts";
import { loadAccounts, removeAccount, tokenStore } from "../platform/accounts.ts";
import { broadcast } from "../platform/messages.ts";
import { clearUnlocked, getRing, isUnlocked, persistUserKey } from "../platform/session.ts";
import { loadSettings, LockTimeout } from "../platform/settings.ts";
import { local, session } from "../platform/storage.ts";
import { forgetApi } from "./ctx.ts";
import { refreshIcon } from "./icon.ts";

export async function lock(accountId?: string, all = false): Promise<void> {
  const s = await loadAccounts();
  const ids = all ? s.list.map((a) => a.id) : [accountId ?? s.active].filter(Boolean) as string[];
  for (const id of ids) {
    await clearUnlocked(id);
    await chrome.alarms.clear(`lock:${id}`);
    broadcast({ kind: "lock", accountId: id });
  }
  // PIN that does not survive restarts must not survive a manual lock either? It does: like the
  // official client, PIN unlock stays available until browser restart.
  await refreshIcon();
}

export async function logout(accountId: string): Promise<void> {
  await clearUnlocked(accountId);
  await chrome.alarms.clear(`lock:${accountId}`);
  await tokenStore(accountId).set(null);
  await removeAccount(accountId);
  // Everything else kept per account ("<what>:<account id>"): generator history, forwarder keys,
  // PIN, sync state and anything added later.
  for (const area of [local, session]) {
    const keys = Object.keys(await area.all()).filter((k) => k.endsWith(`:${accountId}`));
    if (keys.length) await area.remove(keys);
  }
  forgetApi(accountId);
  await VaultDB.destroy(accountId);
  broadcast({ kind: "accounts" });
  broadcast({ kind: "lock", accountId });
  await refreshIcon();
}

/** Refresh token rejected: keep local data, require a new login. */
export async function onLoggedOut(accountId: string): Promise<void> {
  await clearUnlocked(accountId);
  await local.set(`needsLogin:${accountId}`, true);
  broadcast({ kind: "lock", accountId });
  await refreshIcon();
}

let lastActivity = 0;

/** Called on popup open, fills, etc. Pushes the lock deadline (debounced to 30 s). */
export async function activity(accountId?: string): Promise<void> {
  const now = Date.now();
  if (now - lastActivity < 30_000) return;
  lastActivity = now;
  const settings = await loadSettings();
  if (settings.lockTimeout <= 0) return; // on restart / never / immediately are handled elsewhere
  const s = await loadAccounts();
  const id = accountId ?? s.active;
  if (!id || !(await isUnlocked(id))) return;
  await chrome.alarms.create(`lock:${id}`, { when: now + settings.lockTimeout * 60_000 });
}

export async function onLockAlarm(accountId: string): Promise<void> {
  const settings = await loadSettings();
  if (settings.timeoutAction === "logout") await logout(accountId);
  else await lock(accountId);
}

// Every "never lock" key write goes through one queue. Unqueued, an unlock that read "Never"
// could write its key after a settings change to another timeout had already removed it.
let neverLockQueue: Promise<unknown> = Promise.resolve();
function queueNeverLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = neverLockQueue.then(fn);
  neverLockQueue = run.catch(() => {});
  return run;
}

export function applyNeverLock(accountId: string, ring: import("../core/vault/cipher.ts").KeyRing | null): Promise<void> {
  // Settings are read inside the queue: a change written before this runs is seen here, and the
  // storage event of a later one queues its onSettingsChanged behind this.
  return queueNeverLock(async () => {
    const settings = await loadSettings();
    if (settings.lockTimeout !== LockTimeout.Never) return dropNeverLockKeys();
    await persistUserKey(accountId, ring && (await isUnlocked(accountId)) ? ring : null);
  });
}

/** Not "never" any more: drop every account's kept key. */
export function forgetNeverLock(): Promise<void> {
  return queueNeverLock(dropNeverLockKeys);
}

// Every account, not only the one at hand: a worker that is still starting after a browser restart
// can miss the storage event of leaving "never", which would leave the other accounts' keys behind.
async function dropNeverLockKeys(): Promise<void> {
  for (const a of (await loadAccounts()).list) await persistUserKey(a.id, null);
}

/** Settings changed: re-apply "never lock" persistence and reset the lock deadline. */
export async function onSettingsChanged(oldTimeout: number | undefined, newTimeout: number): Promise<void> {
  if (oldTimeout === newTimeout) return;
  await queueNeverLock(() => reapplyNeverLock(newTimeout));
  lastActivity = 0;
  await activity();
}

async function reapplyNeverLock(newTimeout: number): Promise<void> {
  const s = await loadAccounts();
  for (const a of s.list) {
    // Leaving "never": drop every kept key, locked accounts included. Entering it: keep the keys
    // of the accounts that are unlocked now (the others are kept on their next unlock).
    if (newTimeout !== LockTimeout.Never) await persistUserKey(a.id, null);
    else {
      const ring = await getRing(a.id);
      if (ring) await persistUserKey(a.id, ring);
    }
    await chrome.alarms.clear(`lock:${a.id}`);
  }
}
