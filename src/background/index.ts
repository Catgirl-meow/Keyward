// Background entry. Every listener is registered synchronously at top level and nothing else
// runs at startup: waking the worker costs only what the triggering event needs.
import { SymKey } from "../core/crypto/symkey.ts";
import { loadAccounts } from "../platform/accounts.ts";
import { serve } from "../platform/messages.ts";
import { getRing, isUnlocked, setUnlocked } from "../platform/session.ts";
import { loadSettings, LockTimeout } from "../platform/settings.ts";
import { local } from "../platform/storage.ts";
import { copy, onClearAlarm, scheduleClear } from "./clipboard.ts";
import { refreshIcon } from "./icon.ts";
import { activity, applyNeverLock, forgetNeverLock, lock, logout, onLockAlarm, onSettingsChanged } from "./lock.ts";
import { syncAccount } from "./sync.ts";
import { ctx, setRestoreHook } from "./ctx.ts";
import { deriveOrgKeys } from "../core/sync/sync.ts";
import { webauthnTwoFactor } from "./webauthn2fa.ts";
import { vaultHandlers } from "./vault.ts";
import { autofillHandlers, onAutofillCommand, onContextMenu, installContextMenus, onTabEvent, onTabUpdated, contentMessage } from "./autofill.ts";
import { saveHandlers } from "./save.ts";
import { installBasicAuth } from "./basicauth.ts";
import { dropPasskeyTab, passkeyHandlers, passkeyMessage, syncPasskeyScripts } from "./passkey.ts";

async function afterUnlock(accountId: string, userKeyB64: string, firstLogin: boolean) {
  const user = SymKey.fromB64(userKeyB64);
  // The list needs only the user key (summaries are sealed with a key derived from it), so pages
  // get an answer as soon as it is in session storage; everything else happens afterwards.
  const previous = (await getRing(accountId))?.orgs ?? new Map<string, SymKey>();
  await setUnlocked(accountId, { user, orgs: previous });
  await local.remove(`needsLogin:${accountId}`);
  void (async () => {
    try {
      // Org keys come from the stored profile so an unlock works offline and without a full sync.
      const { db } = await ctx(accountId);
      const orgs = await deriveOrgKeys(await db.meta("profile"), user, previous);
      if (orgs.size || previous.size) await setUnlocked(accountId, { user, orgs });
    } catch {}
    const ring = (await getRing(accountId))!;
    await applyNeverLock(accountId, ring);
    await chrome.alarms.create("sync", { periodInMinutes: 5 });
    await refreshIcon();
    await activity(accountId);
    await syncAccount(accountId, firstLogin);
  })();
  return { synced: false };
}

serve(
  {
    "auth.webauthn2fa": ({ remember }) => webauthnTwoFactor(remember, (id, key) => afterUnlock(id, key, true)),
    "session.loginComplete": ({ accountId, userKey }) => afterUnlock(accountId, userKey, true),
    "session.unlocked": ({ accountId, userKey }) => afterUnlock(accountId, userKey, false),
    "session.lock": ({ accountId, all } = {} as any) => lock(accountId, all),
    "session.logout": ({ accountId }) => logout(accountId),
    "session.activity": async (arg) => {
      await activity(arg?.accountId);
      const s = await loadAccounts();
      const id = arg?.accountId ?? s.active;
      if (id && (await isUnlocked(id))) void syncAccount(id, false);
    },
    "sync.now": ({ accountId, force }) => syncAccount(accountId, force ?? true),
    "clipboard.copy": async ({ text, sensitive }) => {
      // Pages copy themselves; this path schedules the clear (and copies for background callers).
      if (sensitive === false) return;
      await scheduleClear(text);
    },
    "ui.openVault": async (arg) => {
      await chrome.tabs.create({ url: chrome.runtime.getURL("vault.html" + (arg?.path ? `#${arg.path}` : "")) });
    },
    ...vaultHandlers,
    ...autofillHandlers,
    ...saveHandlers,
    ...passkeyHandlers,
  },
  (msg, sender, respond) => contentMessage(msg, sender, respond) || passkeyMessage(msg, sender, respond),
);

chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === "clip-clear") return onClearAlarm();
  if (a.name.startsWith("lock:")) return onLockAlarm(a.name.slice(5));
  if (a.name === "sync") {
    const s = await loadAccounts();
    let any = false;
    for (const acc of s.list) {
      if (await isUnlocked(acc.id)) {
        any = true;
        await syncAccount(acc.id, false).catch(() => {});
      }
    }
    if (!any) await chrome.alarms.clear("sync");
  }
});

async function restoreNeverLock(accountId: string): Promise<boolean> {
  const key = await local.get<string>(`persistKey:${accountId}`);
  if (!key || (await local.get(`needsLogin:${accountId}`))) return false;
  // A key left behind after leaving "never" (see forgetNeverLock) must not unlock anything.
  if ((await loadSettings()).lockTimeout !== LockTimeout.Never) {
    await forgetNeverLock();
    return false;
  }
  await afterUnlock(accountId, key, false);
  return true;
}
setRestoreHook(restoreNeverLock);

chrome.runtime.onStartup.addListener(async () => {
  const s = await loadAccounts();
  for (const a of s.list) if (!(await isUnlocked(a.id))) await restoreNeverLock(a.id);
  await refreshIcon();
  await syncPasskeyScripts();
});

chrome.runtime.onInstalled.addListener(async () => {
  await installContextMenus();
  await refreshIcon();
  await syncPasskeyScripts();
});

chrome.idle.onStateChanged.addListener(async (state) => {
  if (state !== "locked") return;
  const settings = await loadSettings();
  if (settings.lockOnSystemLock) await lock(undefined, true);
});

// "Lock immediately" = lock when the popup closes.
chrome.runtime.onConnect.addListener((port) => {
  if (port.sender?.id !== chrome.runtime.id || port.name !== "popup") return;
  port.onDisconnect.addListener(async () => {
    const settings = await loadSettings();
    if (settings.lockTimeout === LockTimeout.Immediately) await lock(undefined, true);
  });
});

chrome.storage.onChanged.addListener((ch, area) => {
  // Unlock, lock, account switch or the passkey setting: the page shim follows.
  if ((area === "session" && Object.keys(ch).some((k) => k.startsWith("unlocked:"))) || (area === "local" && (ch.settings || ch.accounts))) void syncPasskeyScripts();
  if (area !== "local" || !ch.settings) return;
  const before = (ch.settings.oldValue as { lockTimeout?: number } | undefined)?.lockTimeout;
  const after = (ch.settings.newValue as { lockTimeout?: number } | undefined)?.lockTimeout ?? LockTimeout.OnRestart;
  void onSettingsChanged(before, after);
});

chrome.commands.onCommand.addListener((cmd, tab) => onAutofillCommand(cmd, tab));
chrome.contextMenus.onClicked.addListener((info, tab) => onContextMenu(info, tab));
chrome.tabs.onActivated.addListener(({ tabId }) => onTabEvent(tabId));
chrome.tabs.onUpdated.addListener(onTabUpdated);
installBasicAuth();
chrome.tabs.onRemoved.addListener((tabId) => {
  onTabEvent(tabId, true);
  void dropPasskeyTab(tabId);
});
