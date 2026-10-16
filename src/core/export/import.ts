// Import: Bitwarden JSON (plain, encrypted for this account, protected by a password),
// Bitwarden CSV, and the password CSVs browsers export (Chromium, Firefox, Safari).
// Everything becomes CipherViews plus folder names; the background encrypts and uploads them.
import { decryptString } from "../crypto/encstring.ts";
import { deriveKey, readKdf, stretchKey, type Argon2Fn } from "../crypto/kdf.ts";
import type { SymKey } from "../crypto/symkey.ts";
import { decryptCipher, emptyView } from "../vault/cipher.ts";
import { CARD_FIELDS, CipherType, FieldType, IDENTITY_FIELDS, type CipherView, type FieldView, type LoginView, type RawCipher, type UriMatch } from "../vault/types.ts";
import { csvRecords } from "./csv.ts";

export type ImportFormat = "bitwarden_json" | "bitwarden_encrypted_json" | "bitwarden_password_json" | "bitwarden_csv" | "chromium_csv" | "firefox_csv" | "safari_csv";

export const FORMAT_LABEL: Record<ImportFormat, string> = {
  bitwarden_json: "Bitwarden JSON",
  bitwarden_encrypted_json: "Bitwarden JSON, encrypted for an account",
  bitwarden_password_json: "Bitwarden JSON, protected by a password",
  bitwarden_csv: "Bitwarden CSV",
  chromium_csv: "Chrome / Chromium / Helium CSV",
  firefox_csv: "Firefox / LibreWolf CSV",
  safari_csv: "Safari CSV",
};

export interface ImportResult {
  format: ImportFormat;
  items: CipherView[];
  /** Folder names; `relations` puts item i into folder j. */
  folders: string[];
  relations: [number, number][];
}

export class ImportError extends Error {
  code: "format" | "password" | "account" | "empty";
  constructor(message: string, code: ImportError["code"] = "format") {
    super(message);
    this.code = code;
  }
}

/** Which format a file is in, without decrypting anything. */
export function detectFormat(text: string): ImportFormat | null {
  const t = text.replace(/^﻿/, "").trimStart();
  if (t.startsWith("{")) {
    try {
      const j = JSON.parse(t);
      if (j?.passwordProtected) return "bitwarden_password_json";
      if (j?.encrypted === true && Array.isArray(j.items)) return "bitwarden_encrypted_json";
      if (Array.isArray(j?.items)) return "bitwarden_json";
    } catch {
      return null;
    }
    return null;
  }
  const head = new Set(t.split(/\r?\n/, 1)[0].split(",").map((k) => k.replace(/"/g, "").trim().toLowerCase()));
  const has = (...k: string[]) => k.every((x) => head.has(x));
  if (has("name", "login_uri", "login_username", "login_password")) return "bitwarden_csv";
  if (has("url", "username", "password") && (head.has("httprealm") || head.has("guid"))) return "firefox_csv";
  if (has("title", "url", "username", "password")) return "safari_csv";
  if (has("name", "url", "username", "password")) return "chromium_csv";
  return null;
}

const str = (x: unknown): string | null => (x == null || x === "" ? null : String(x));

function login(username: string | null, password: string | null, uris: string[], totp: string | null = null): LoginView {
  return {
    username, password, passwordRevisionDate: null, totp,
    uris: uris.map((u) => u.trim()).filter(Boolean).map((uri) => ({ uri, match: null })),
    autofillOnPageLoad: null, fido2Credentials: [],
  };
}

/** One item of Bitwarden's plain export JSON. Unknown or missing parts are left empty. */
function fromBitwardenItem(o: any): CipherView {
  const type = [1, 2, 3, 4, 5].includes(Number(o.type)) ? (Number(o.type) as CipherType) : CipherType.SecureNote;
  const v = emptyView(type, {
    name: str(o.name) ?? "(no name)",
    notes: str(o.notes),
    favorite: !!o.favorite,
    reprompt: o.reprompt === 1 ? 1 : 0,
    archivedDate: str(o.archivedDate),
    fields: Array.isArray(o.fields)
      ? o.fields.map((f: any): FieldView => ({ type: ([0, 1, 2, 3].includes(Number(f?.type)) ? Number(f.type) : FieldType.Text) as FieldType, name: str(f?.name), value: str(f?.value), linkedId: f?.linkedId ?? null }))
      : [],
    passwordHistory: Array.isArray(o.passwordHistory)
      ? o.passwordHistory.filter((h: any) => h?.password).map((h: any) => ({ password: String(h.password), lastUsedDate: str(h.lastUsedDate) ?? new Date().toISOString() }))
      : [],
  });
  if (type === CipherType.Login) {
    const l = o.login ?? {};
    v.login = {
      ...login(str(l.username), str(l.password), [], str(l.totp)),
      uris: Array.isArray(l.uris) ? l.uris.filter((u: any) => str(u?.uri)).map((u: any) => ({ uri: String(u.uri), match: (u.match == null ? null : Number(u.match)) as UriMatch | null })) : [],
      fido2Credentials: Array.isArray(l.fido2Credentials)
        ? l.fido2Credentials.filter((f: any) => f?.credentialId && f?.keyValue).map((f: any) => ({
            credentialId: String(f.credentialId), keyType: str(f.keyType) ?? "public-key", keyAlgorithm: str(f.keyAlgorithm) ?? "ECDSA", keyCurve: str(f.keyCurve) ?? "P-256",
            keyValue: String(f.keyValue), rpId: String(f.rpId ?? ""), userHandle: str(f.userHandle), userName: str(f.userName), counter: Number(f.counter ?? 0) || 0,
            rpName: str(f.rpName), userDisplayName: str(f.userDisplayName), discoverable: String(f.discoverable) === "true", creationDate: str(f.creationDate) ?? new Date().toISOString(),
          }))
        : [],
    };
  } else if (type === CipherType.Card) {
    v.card = Object.fromEntries(CARD_FIELDS.map((k) => [k, str(o.card?.[k])])) as any;
  } else if (type === CipherType.Identity) {
    v.identity = Object.fromEntries(IDENTITY_FIELDS.map((k) => [k, str(o.identity?.[k])])) as any;
  } else if (type === CipherType.SshKey) {
    v.sshKey = { privateKey: str(o.sshKey?.privateKey), publicKey: str(o.sshKey?.publicKey), keyFingerprint: str(o.sshKey?.keyFingerprint) };
  }
  return v;
}

function withFolders(format: ImportFormat, items: CipherView[], folderOf: (string | null)[], folders: { id: string; name: string }[]): ImportResult {
  const names: string[] = [];
  const index = new Map<string, number>();
  const relations: [number, number][] = [];
  folderOf.forEach((fid, i) => {
    const name = fid == null ? null : folders.find((f) => f.id === fid)?.name ?? null;
    if (!name) return;
    if (!index.has(name)) index.set(name, names.push(name) - 1);
    relations.push([i, index.get(name)!]);
  });
  return { format, items, folders: names, relations };
}

function fromBitwardenJson(j: any, format: ImportFormat = "bitwarden_json"): ImportResult {
  const raw = Array.isArray(j.items) ? j.items.filter((o: any) => o && !o.deletedDate) : [];
  const folders = Array.isArray(j.folders) ? j.folders.filter((f: any) => f?.id && f?.name).map((f: any) => ({ id: String(f.id), name: String(f.name) })) : [];
  return withFolders(format, raw.map(fromBitwardenItem), raw.map((o: any) => str(o.folderId)), folders);
}

async function fromAccountEncrypted(j: any, userKey: SymKey): Promise<ImportResult> {
  try {
    await decryptString(j.encKeyValidation_DO_NOT_EDIT, userKey);
  } catch {
    throw new ImportError("This file was exported from another account; only that account can import it.", "account");
  }
  const ring = { user: userKey, orgs: new Map() };
  const raw = (j.items as any[]).filter((o) => o && !o.deletedDate);
  const items = await Promise.all(raw.map(async (o) => {
    const v = await decryptCipher({ ...o, organizationId: null, collectionIds: [] } as RawCipher, ring);
    return { ...v, id: "", organizationId: null, collectionIds: [], attachments: [], errors: [] };
  }));
  const folders = await Promise.all((Array.isArray(j.folders) ? j.folders : []).map(async (f: any) => ({ id: String(f.id), name: await decryptString(f.name, userKey).catch(() => "Imported") })));
  return withFolders("bitwarden_encrypted_json", items, raw.map((o) => str(o.folderId)), folders);
}

async function fromPasswordProtected(j: any, password: string, argon2?: Argon2Fn): Promise<ImportResult> {
  const kdf = readKdf({ kdfType: j.kdfType, kdfIterations: j.kdfIterations, kdfMemory: j.kdfMemory, kdfParallelism: j.kdfParallelism });
  const key = await stretchKey(await deriveKey(password, String(j.salt), kdf, argon2));
  try {
    await decryptString(j.encKeyValidation_DO_NOT_EDIT, key);
  } catch {
    throw new ImportError("Wrong password for this file", "password");
  }
  const inner = JSON.parse(await decryptString(j.data, key));
  return fromBitwardenJson(inner, "bitwarden_password_json");
}

const hostName = (url: string) => {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
};

function fromBitwardenCsv(rows: Record<string, string>[]): ImportResult {
  const folderOf: (string | null)[] = [];
  const items = rows.map((r) => {
    const note = r.type?.trim().toLowerCase() === "note";
    const v = emptyView(note ? CipherType.SecureNote : CipherType.Login, {
      name: r.name || "(no name)",
      notes: str(r.notes),
      favorite: r.favorite === "1" || r.favorite?.toLowerCase() === "true",
      reprompt: r.reprompt === "1" ? 1 : 0,
      fields: (r.fields ?? "").split(/\r?\n/).filter((l) => l.trim()).map((l) => {
        const at = l.indexOf(": ");
        return { type: FieldType.Text, name: at < 0 ? l : l.slice(0, at), value: at < 0 ? null : l.slice(at + 2), linkedId: null };
      }),
    });
    if (!note) v.login = login(str(r.login_username), str(r.login_password), (r.login_uri ?? "").split(","), str(r.login_totp));
    folderOf.push(str(r.folder));
    return v;
  });
  const names = [...new Set(folderOf.filter((f): f is string => !!f))];
  return withFolders("bitwarden_csv", items, folderOf, names.map((n) => ({ id: n, name: n })));
}

function fromBrowserCsv(format: "chromium_csv" | "firefox_csv" | "safari_csv", rows: Record<string, string>[]): ImportResult {
  const items = rows
    .filter((r) => r.url || r.username || r.password)
    .map((r) => {
      const url = r.url ?? "";
      const name = (format === "safari_csv" ? r.title : format === "chromium_csv" ? r.name : "") || hostName(url) || "(no name)";
      const totp = format === "safari_csv" ? str(r.otpauth) : null;
      return emptyView(CipherType.Login, { name, notes: str(r.note ?? r.notes), login: login(str(r.username), str(r.password), [url], totp) });
    });
  return { format, items, folders: [], relations: [] };
}

/**
 * Parses an export. `userKey` opens a file encrypted for this account; `password` one protected
 * by a password (ImportError code "password" when it's missing or wrong).
 */
export async function parseImport(text: string, opts: { userKey?: SymKey; password?: string; argon2?: Argon2Fn } = {}): Promise<ImportResult> {
  const format = detectFormat(text);
  if (!format) throw new ImportError("Not a file Keyward can import. Use a Bitwarden JSON or CSV export, or a browser's password CSV.");
  let r: ImportResult;
  if (format.endsWith("_json")) {
    const j = JSON.parse(text.replace(/^﻿/, ""));
    if (format === "bitwarden_password_json") {
      if (!opts.password) throw new ImportError("This file is protected by a password", "password");
      r = await fromPasswordProtected(j, opts.password, opts.argon2);
    } else if (format === "bitwarden_encrypted_json") {
      if (!opts.userKey) throw new ImportError("Unlock the vault to import an encrypted file", "account");
      r = await fromAccountEncrypted(j, opts.userKey);
    } else r = fromBitwardenJson(j);
  } else {
    const rows = csvRecords(text);
    r = format === "bitwarden_csv" ? fromBitwardenCsv(rows) : fromBrowserCsv(format as "chromium_csv", rows);
  }
  if (!r.items.length) throw new ImportError("There are no items in this file", "empty");
  return r;
}
