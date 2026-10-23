// Account registry + per-account Api construction (usable from SW and pages).
import { Api, serverUrls, type ClientInfo, type TokenStore, type Tokens } from "../core/api/client.ts";
import type { Kdf } from "../core/crypto/kdf.ts";
import { local } from "./storage.ts";

export const DEFAULT_SERVER = __DEFAULT_SERVER__;
export const CLIENT_VERSION = "2026.9.3"; // what Vaultwarden gates features on; keep current

export interface Account {
  id: string; // user id (JWT sub)
  email: string;
  name: string | null;
  server: string;
  kdf: Kdf;
  protectedUserKey: string;
  localHash: string;
  addedAt: number;
}

export interface AccountsState {
  active: string | null;
  list: Account[];
}

export async function loadAccounts(): Promise<AccountsState> {
  return (await local.get<AccountsState>("accounts")) ?? { active: null, list: [] };
}

export async function saveAccounts(s: AccountsState): Promise<void> {
  await local.set("accounts", s);
}

export async function activeAccount(): Promise<Account | null> {
  const s = await loadAccounts();
  return s.list.find((a) => a.id === s.active) ?? s.list[0] ?? null;
}

export async function upsertAccount(a: Account, makeActive = true): Promise<void> {
  const s = await loadAccounts();
  const i = s.list.findIndex((x) => x.id === a.id);
  if (i >= 0) s.list[i] = { ...s.list[i], ...a };
  else s.list.push(a);
  if (makeActive) s.active = a.id;
  await saveAccounts(s);
}

export async function removeAccount(id: string): Promise<void> {
  const s = await loadAccounts();
  s.list = s.list.filter((a) => a.id !== id);
  if (s.active === id) s.active = s.list[0]?.id ?? null;
  await saveAccounts(s);
  await local.remove([`tokens:${id}`, `pin:${id}`]);
}

export async function deviceId(): Promise<string> {
  let d = await local.get<string>("deviceId");
  if (!d) {
    d = crypto.randomUUID();
    await local.set("deviceId", d);
  }
  return d;
}

export async function clientInfo(): Promise<ClientInfo> {
  return {
    deviceType: __FIREFOX__ ? 3 : 2,
    deviceName: __FIREFOX__ ? "firefox" : "chrome",
    deviceId: await deviceId(),
    clientVersion: CLIENT_VERSION,
  };
}

export function tokenStore(accountId: string): TokenStore {
  const key = `tokens:${accountId}`;
  return {
    get: () => local.get<Tokens>(key).then((t) => t ?? null),
    set: (t) => (t ? local.set(key, t) : local.remove(key)),
  };
}

export async function apiFor(account: Pick<Account, "id" | "server"> | null, server?: string): Promise<Api> {
  return new Api(serverUrls(account?.server ?? server ?? DEFAULT_SERVER), await clientInfo(), account ? tokenStore(account.id) : null);
}

export async function hasTokens(accountId: string): Promise<boolean> {
  return !!(await local.get(`tokens:${accountId}`));
}
