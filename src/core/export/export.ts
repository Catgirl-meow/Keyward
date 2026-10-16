// Vault export in Bitwarden's formats, so the official apps (and Keyguard) can import it:
// JSON, JSON encrypted for this account, JSON protected by a password, and CSV.
// Only the personal vault is exported: no organization items, no trash, no attachments.
import { encryptString } from "../crypto/encstring.ts";
import { deriveKey, stretchKey, type Argon2Fn, type Kdf } from "../crypto/kdf.ts";
import type { SymKey } from "../crypto/symkey.ts";
import { randomBytes, toB64 } from "../util/bytes.ts";
import { CipherType, FieldType, IDENTITY_FIELDS, type CipherView, type RawCipher } from "../vault/types.ts";
import { toCsv } from "./csv.ts";

export type ExportFormat = "json" | "encrypted_json" | "password_json" | "csv";

/** What gets exported: personal, not deleted. */
export const exportable = (v: Pick<CipherView, "organizationId" | "deletedDate">) => !v.organizationId && !v.deletedDate;

/** One item in Bitwarden's export JSON (CipherWithIdExport). */
export function exportItem(v: CipherView) {
  return {
    passwordHistory: v.passwordHistory.length ? v.passwordHistory.map((h) => ({ lastUsedDate: h.lastUsedDate, password: h.password })) : null,
    revisionDate: v.revisionDate,
    creationDate: v.creationDate,
    deletedDate: null,
    archivedDate: v.archivedDate,
    id: v.id,
    organizationId: null,
    folderId: v.folderId,
    type: v.type,
    reprompt: v.reprompt,
    name: v.name,
    notes: v.notes,
    favorite: v.favorite,
    fields: v.fields.length ? v.fields.map((f) => ({ name: f.name, value: f.value, type: f.type, linkedId: f.linkedId })) : undefined,
    login: v.type === CipherType.Login && v.login
      ? {
          fido2Credentials: v.login.fido2Credentials.map((f) => ({
            credentialId: f.credentialId, keyType: f.keyType, keyAlgorithm: f.keyAlgorithm, keyCurve: f.keyCurve, keyValue: f.keyValue,
            rpId: f.rpId, userHandle: f.userHandle, userName: f.userName, counter: String(f.counter), rpName: f.rpName,
            userDisplayName: f.userDisplayName, discoverable: String(f.discoverable), creationDate: f.creationDate,
          })),
          uris: v.login.uris.map((u) => ({ match: u.match, uri: u.uri })),
          username: v.login.username,
          password: v.login.password,
          totp: v.login.totp,
        }
      : undefined,
    secureNote: v.type === CipherType.SecureNote ? { type: 0 } : undefined,
    card: v.type === CipherType.Card && v.card ? { ...v.card } : undefined,
    identity: v.type === CipherType.Identity && v.identity ? Object.fromEntries(IDENTITY_FIELDS.map((k) => [k, v.identity![k]])) : undefined,
    sshKey: v.type === CipherType.SshKey && v.sshKey ? { ...v.sshKey } : undefined,
    collectionIds: null,
  };
}

/** Plain JSON: everything readable by anyone who gets the file. */
export function exportJson(views: CipherView[], folders: { id: string; name: string }[]): string {
  const items = views.filter(exportable);
  const used = new Set(items.map((v) => v.folderId));
  return JSON.stringify({ encrypted: false, folders: folders.filter((f) => used.has(f.id)).map((f) => ({ id: f.id, name: f.name })), items: items.map(exportItem) }, null, 2);
}

/**
 * JSON whose items stay encrypted with this account's key ("account restricted"): only this
 * account can import it. The items are the server's own encrypted form.
 */
export async function exportAccountEncrypted(raws: RawCipher[], rawFolders: { id: string; name: string }[], userKey: SymKey): Promise<string> {
  const items = raws.filter((r) => !r.organizationId && !r.deletedDate);
  const used = new Set(items.map((r) => r.folderId));
  const pick = (r: RawCipher) => {
    const o: Record<string, unknown> = {};
    for (const k of ["passwordHistory", "revisionDate", "creationDate", "archivedDate", "id", "organizationId", "folderId", "type", "reprompt", "name", "notes", "favorite", "fields", "login", "secureNote", "card", "identity", "sshKey", "key"]) {
      if ((r as any)[k] !== undefined) o[k] = (r as any)[k];
    }
    return { ...o, deletedDate: null, collectionIds: null };
  };
  return JSON.stringify(
    {
      encrypted: true,
      encKeyValidation_DO_NOT_EDIT: await encryptString(crypto.randomUUID(), userKey),
      folders: rawFolders.filter((f) => used.has(f.id)).map((f) => ({ id: f.id, name: f.name })),
      items: items.map(pick),
    },
    null,
    2,
  );
}

/**
 * Plain JSON encrypted with a key derived from a password (Bitwarden's "password protected"
 * export): the salt is a base64 string, used as text, and the KDF is the account's.
 */
export async function exportPasswordProtected(json: string, password: string, kdf: Kdf, argon2?: Argon2Fn): Promise<string> {
  const salt = toB64(randomBytes(16));
  const key = await stretchKey(await deriveKey(password, salt, kdf, argon2));
  return JSON.stringify(
    {
      encrypted: true,
      passwordProtected: true,
      salt,
      kdfType: kdf.type,
      kdfIterations: kdf.iterations,
      kdfMemory: kdf.memory ?? undefined,
      kdfParallelism: kdf.parallelism ?? undefined,
      encKeyValidation_DO_NOT_EDIT: await encryptString(crypto.randomUUID(), key),
      data: await encryptString(json, key),
    },
    null,
    2,
  );
}

export const CSV_HEAD = ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"];

/** Bitwarden's CSV: logins and notes only (the format has no columns for the other types). */
export function exportCsv(views: CipherView[], folderNames: Map<string, string>): string {
  const rows = views
    .filter((v) => exportable(v) && (v.type === CipherType.Login || v.type === CipherType.SecureNote))
    .map((v) => [
      v.folderId ? folderNames.get(v.folderId) ?? "" : "",
      v.favorite ? 1 : "",
      v.type === CipherType.Login ? "login" : "note",
      v.name,
      v.notes,
      v.fields.filter((f) => f.type !== FieldType.Linked).map((f) => `${f.name ?? ""}: ${f.value ?? ""}`).join("\n"),
      v.reprompt,
      v.login?.uris.map((u) => u.uri).join(","),
      v.login?.username,
      v.login?.password,
      v.login?.totp,
    ]);
  return toCsv(CSV_HEAD, rows);
}

/** Items the CSV format can't hold (cards, identities, SSH keys). */
export const csvSkipped = (views: CipherView[]) => views.filter((v) => exportable(v) && v.type !== CipherType.Login && v.type !== CipherType.SecureNote).length;

/** keyward_export_20261016134501.json */
export function exportFileName(format: ExportFormat, now = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  const stamp = `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`;
  return `keyward_export_${stamp}.${format === "csv" ? "csv" : "json"}`;
}
