// UI state shared by the popup and the full-tab vault. Pages read storage/IndexedDB directly
// (no service-worker round trip before first paint) and send writes to the background.
import { computed, effect, signal } from "@preact/signals";
import type { RawSend } from "../../core/send/send.ts";
import { VaultDB } from "../../core/store/db.ts";
import { loadSnapshot, type AuxData } from "../../core/store/summaries.ts";
import { decryptCipher, type KeyRing } from "../../core/vault/cipher.ts";
import type { CipherView, RawCipher, Summary } from "../../core/vault/types.ts";
import { loadAccounts, saveAccounts, type Account, type AccountsState } from "../../platform/accounts.ts";
import { listen, rpc, type SyncStatus } from "../../platform/messages.ts";
import { getCacheKey, getRing, setUnlocked } from "../../platform/session.ts";
import { SymKey } from "../../core/crypto/symkey.ts";
import { DEFAULT_SETTINGS, loadSettings, LockTimeout, saveSettings, type Settings } from "../../platform/settings.ts";
import { local, onChanged, session } from "../../platform/storage.ts";
import { applyTheme, watchSystemTheme } from "../theme/theme.ts";

export type Phase = "boot" | "login" | "locked" | "unlocked";

export const settings = signal<Settings>(DEFAULT_SETTINGS);
export const accounts = signal<AccountsState>({ active: null, list: [] });
export const account = computed<Account | null>(() => accounts.value.list.find((a) => a.id === accounts.value.active) ?? accounts.value.list[0] ?? null);
export const phase = signal<Phase>("boot");
export const items = signal<Map<string, Summary>>(new Map());
export const aux = signal<AuxData>({ folders: [], collections: [], orgs: [] });
export const vaultLoaded = signal(false);
export const syncStatus = signal<SyncStatus | null>(null);
export const syncing = signal(false);
export const needsLogin = signal(false);
/** Login screen shown on top of an existing account ("Add account"). */
export const addingAccount = signal(false);

let ring: KeyRing | null = null;
let db: VaultDB | null = null;

export const folderNames = computed(() => new Map(aux.value.folders.map((f) => [f.id, f.name])));
export const orgNames = computed(() => new Map(aux.value.orgs.map((o) => [o.id, o.name])));

export function currentRing(): KeyRing | null {
  return ring;
}

const mark = (n: string) => performance.mark(`kw:${n}`);

export async function boot(): Promise<void> {
  mark("boot");
  const [s, a] = await Promise.all([loadSettings(), loadAccounts()]);
  mark("settings");
  settings.value = s;
  applyTheme(s);
  watchSystemTheme(() => settings.value);
  accounts.value = a;
  await refreshPhase();
  listen(async (m) => {
    if (m.kind === "vault" && m.accountId === account.value?.id) await loadVault();
    else if (m.kind === "lock" && (m.accountId === account.value?.id || m.accountId == null)) await refreshPhase();
    else if (m.kind === "accounts") {
      accounts.value = await loadAccounts();
      await refreshPhase();
    } else if (m.kind === "sync" && m.accountId === account.value?.id) {
      syncStatus.value = m.status;
      syncing.value = false;
    } else if (m.kind === "settings") {
      settings.value = await loadSettings();
      applyTheme(settings.value);
    }
  });
  onChanged((ch, area) => {
    if (area === "local" && ch.settings) {
      settings.value = { ...DEFAULT_SETTINGS, ...(ch.settings.newValue as Settings) };
      applyTheme(settings.value);
    }
  });
}

export async function refreshPhase(): Promise<void> {
  accounts.value = await loadAccounts();
  const a = account.value;
  if (!a) {
    phase.value = "login";
    ring = null;
    return;
  }
  needsLogin.value = !!(await local.get(`needsLogin:${a.id}`));
  ring = needsLogin.value ? null : await getRing(a.id);
  if (!ring && !needsLogin.value) {
    // "Never lock": after a browser restart the key is on disk; unlock through the background
    // (org keys, alarms, sync) exactly as a password unlock would.
    const persisted = await local.get<string>(`persistKey:${a.id}`);
    // Only while the timeout is still "Never": a leftover key is the background's to drop.
    if (persisted && (await loadSettings()).lockTimeout === LockTimeout.Never) {
      // Put the key in session storage here, so the list doesn't wait for the service worker to
      // start; the background then derives org keys, sets alarms and syncs on its own time.
      await setUnlocked(a.id, { user: SymKey.fromB64(persisted), orgs: new Map() });
      ring = await getRing(a.id);
      void rpc("session.unlocked", { accountId: a.id, userKey: persisted, via: "password" }).catch(() => {});
    }
  }
  if (!ring) {
    phase.value = "locked";
    items.value = new Map();
    vaultLoaded.value = false;
    return;
  }
  mark("ring");
  phase.value = "unlocked";
  syncStatus.value = (await session.get<SyncStatus>(`sync:${a.id}`)) ?? null;
  await loadVault();
}

export async function loadVault(): Promise<void> {
  const a = account.value;
  if (!a) return;
  ring = await getRing(a.id);
  const key = await getCacheKey(a.id);
  if (!ring || !key) {
    phase.value = "locked";
    return;
  }
  db = await VaultDB.open(a.id);
  mark("db");
  const snap = await loadSnapshot(db, key);
  mark("snapshot");
  items.value = snap.items;
  aux.value = snap.aux;
  vaultLoaded.value = true;
}

export async function openItem(id: string): Promise<{ view: CipherView; raw: RawCipher } | null> {
  if (!db || !ring) return null;
  const raw = await db.getCipher(id);
  if (!raw) return null;
  return { view: await decryptCipher(raw, ring), raw };
}

export async function rawSends(): Promise<RawSend[]> {
  return (await db?.getAll<RawSend>("sends")) ?? [];
}

export async function rawItem(id: string): Promise<RawCipher | undefined> {
  return db?.getCipher(id);
}

export async function syncNow(force = true): Promise<void> {
  syncing.value = true;
  try {
    syncStatus.value = await rpc("sync.now", { force });
  } finally {
    syncing.value = false;
  }
}

export async function lockNow(): Promise<void> {
  await rpc("session.lock", { all: true });
  await refreshPhase();
}

export async function switchAccount(id: string | null): Promise<void> {
  const s = await loadAccounts();
  s.active = id;
  await saveAccounts(s);
  await refreshPhase();
}

export async function updateSettings(patch: Partial<Settings>): Promise<void> {
  settings.value = await saveSettings(patch);
  applyTheme(settings.value);
}

export function iconUrl(host: string | null): string | null {
  if (!host || !settings.value.showFavicons || !account.value) return null;
  return `${account.value.server.replace(/\/+$/, "")}/icons/${encodeURIComponent(host)}/icon.png`;
}

effect(() => {
  // Keep document title meaningful for the vault tab.
  if (typeof document !== "undefined" && location.pathname.endsWith("vault.html")) document.title = phase.value === "unlocked" ? "Keyward" : "Keyward — locked";
});
