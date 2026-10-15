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
  await session.remove([`pinSession:${accountId}`, `sync:${accountId}`]);
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

export async function applyNeverLock(accountId: string, ring: import("../core/vault/cipher.ts").KeyRing | null): Promise<void> {
  const settings = await loadSettings();
  await persistUserKey(accountId, settings.lockTimeout === LockTimeout.Never ? ring : null);
}

/** Settings changed: re-apply "never lock" persistence and reset the lock deadline. */
export async function onSettingsChanged(oldTimeout: number | undefined, newTimeout: number): Promise<void> {
  if (oldTimeout === newTimeout) return;
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
  lastActivity = 0;
  await activity();
}
