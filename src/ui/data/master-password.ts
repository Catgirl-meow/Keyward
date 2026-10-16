// The master-password re-prompt for protected items: the password is checked locally against the
// account's stored hash (no server round trip), in the popup, the vault tab and the passkey dialog.
import { deriveMasterKey, masterPasswordHash } from "../../core/crypto/kdf.ts";
import { loadAccounts, type Account } from "../../platform/accounts.ts";
import { lazyArgon2 } from "../../platform/login.ts";

/** `a`: the account to check against (default: the active one). */
export async function verifyMasterPassword(pw: string, a?: Pick<Account, "email" | "kdf" | "localHash"> | null): Promise<boolean> {
  if (a === undefined) {
    const s = await loadAccounts();
    a = s.list.find((x) => x.id === s.active);
  }
  if (!a?.localHash) return false;
  const mk = await deriveMasterKey(pw, a.email, a.kdf, lazyArgon2);
  return (await masterPasswordHash(mk, pw, 2)) === a.localHash;
}
