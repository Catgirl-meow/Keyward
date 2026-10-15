// Per-account context, rebuilt cheaply whenever the service worker wakes.
import type { Api } from "../core/api/client.ts";
import { VaultDB } from "../core/store/db.ts";
import type { KeyRing } from "../core/vault/cipher.ts";
import { apiFor, loadAccounts, type Account } from "../platform/accounts.ts";
import { getCacheKey, getRing } from "../platform/session.ts";

export interface Ctx {
  account: Account;
  api: Api;
  db: VaultDB;
}

export interface UnlockedCtx extends Ctx {
  ring: KeyRing;
  cacheKey: CryptoKey;
}

const apis = new Map<string, Promise<Api>>();

export class LockedError extends Error {
  code = "locked";
  constructor() {
    super("Vault is locked");
  }
}

export class NoAccountError extends Error {
  code = "no-account";
  constructor() {
    super("Not logged in");
  }
}

export async function resolveAccount(accountId?: string | null): Promise<Account> {
  const s = await loadAccounts();
  const a = s.list.find((x) => x.id === (accountId ?? s.active)) ?? (accountId ? undefined : s.list[0]);
  if (!a) throw new NoAccountError();
  return a;
}

export async function ctx(accountId?: string | null): Promise<Ctx> {
  const account = await resolveAccount(accountId);
  let api = apis.get(account.id);
  if (!api) apis.set(account.id, (api = apiFor(account)));
  return { account, api: await api, db: await VaultDB.open(account.id) };
}

let restoreHook: ((accountId: string) => Promise<boolean>) | null = null;
/** Set by the background entry: re-unlocks an account whose key was kept for "never lock". */
export function setRestoreHook(fn: (accountId: string) => Promise<boolean>) {
  restoreHook = fn;
}

export async function unlockedCtx(accountId?: string | null): Promise<UnlockedCtx> {
  const c = await ctx(accountId);
  let [ring, cacheKey] = await Promise.all([getRing(c.account.id), getCacheKey(c.account.id)]);
  if ((!ring || !cacheKey) && restoreHook && (await restoreHook(c.account.id))) {
    [ring, cacheKey] = await Promise.all([getRing(c.account.id), getCacheKey(c.account.id)]);
  }
  if (!ring || !cacheKey) throw new LockedError();
  return { ...c, ring, cacheKey };
}

export function forgetApi(accountId: string) {
  apis.delete(accountId);
}
