// The active account's organization policies, as computed at its last sync (storage.local
// "policies", per account). Read wherever settings or generator options are read.
import type { EffectivePolicy } from "../core/vault/policy.ts";
import { local } from "./storage.ts";

type Stored = Record<string, EffectivePolicy>;

export async function loadPolicy(accountId?: string): Promise<EffectivePolicy | undefined> {
  const r = await local.getMany(["policies", "accounts"]);
  const id = accountId ?? r.accounts?.active;
  return id ? (r.policies as Stored | undefined)?.[id] : undefined;
}

export async function storePolicy(accountId: string, eff: EffectivePolicy | null): Promise<void> {
  const all = { ...((await local.get<Stored>("policies")) ?? {}) };
  if (eff && Object.keys(eff).length > 1) all[accountId] = eff;
  else delete all[accountId];
  await local.set("policies", all);
}
