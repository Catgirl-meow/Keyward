// Bitwarden Send: text or a file shared by link, encrypted with a key only the link carries.
// The key material is 16 random bytes; HKDF(material, "bitwarden-send", "send") gives the 64-byte
// key for the name, text, notes and file. The material itself is stored encrypted with the user
// key (so the owner can rebuild the link) and travels in the link's fragment, never to the
// server. A password is sent as PBKDF2-SHA256(password, material, 100 000), which the server
// hashes again.
import { decryptBytes, decryptOpt, decryptString, encryptBytes, encryptOpt, encryptString } from "../crypto/encstring.ts";
import { hkdf, pbkdf2Sha256 } from "../crypto/primitives.ts";
import { SymKey } from "../crypto/symkey.ts";
import { fromB64Url, randomBytes, toB64, toB64Url, utf8 } from "../util/bytes.ts";

export const SendType = { Text: 0, File: 1 } as const;
export type SendType = (typeof SendType)[keyof typeof SendType];

export const SEND_PASSWORD_ITERATIONS = 100_000;
/** The server refuses a deletion date further away than this. */
export const SEND_MAX_DAYS = 31;

/** A Send as the server returns it (strings are EncStrings under the Send key). */
export interface RawSend {
  id: string;
  accessId: string;
  type: number;
  name: string;
  notes?: string | null;
  key: string;
  text?: { text?: string | null; hidden?: boolean } | null;
  file?: { id?: string; fileName?: string | null; size?: number | string; sizeName?: string } | null;
  maxAccessCount?: number | null;
  accessCount?: number;
  /** Present (the server's hash) when the Send has a password. */
  password?: string | null;
  disabled?: boolean;
  hideEmail?: boolean | null;
  revisionDate?: string;
  expirationDate?: string | null;
  deletionDate: string;
  [k: string]: unknown;
}

export interface SendView {
  id: string;
  accessId: string;
  type: SendType;
  name: string;
  notes: string | null;
  /** The key material, base64url: the last part of the link. */
  material: string;
  text: { text: string; hidden: boolean } | null;
  file: { id: string; fileName: string; size: number; sizeName: string } | null;
  maxAccessCount: number | null;
  accessCount: number;
  hasPassword: boolean;
  disabled: boolean;
  hideEmail: boolean;
  revisionDate: string | null;
  expirationDate: string | null;
  deletionDate: string;
  /** Something failed to decrypt. */
  error?: boolean;
}

/** What the editor produces; `id` and `material` are set when editing an existing Send. */
export interface SendDraft {
  id?: string;
  material?: string;
  type: SendType;
  name: string;
  notes: string | null;
  text: { text: string; hidden: boolean } | null;
  fileName?: string | null;
  maxAccessCount: number | null;
  expirationDate: string | null;
  deletionDate: string;
  disabled: boolean;
  hideEmail: boolean;
}

export function newSendMaterial(): Uint8Array<ArrayBuffer> {
  return randomBytes(16);
}

export async function sendKey(material: Uint8Array): Promise<SymKey> {
  return new SymKey(await hkdf(material, "bitwarden-send", "send", 64));
}

/** What the client sends as the Send's password, both when setting it and when opening one. */
export async function sendPasswordHash(password: string, material: Uint8Array): Promise<string> {
  return toB64(await pbkdf2Sha256(utf8(password), material, SEND_PASSWORD_ITERATIONS, 32));
}

/** The link a recipient opens: the server's web vault, the access id, the key material. */
export function sendLink(server: string, accessId: string, material: string): string {
  return `${server.replace(/\/+$/, "")}/#/send/${accessId}/${material}`;
}

export function parseSendLink(link: string): { server: string; accessId: string; material: Uint8Array } | null {
  const m = link.trim().match(/^(https?:\/\/[^#]+?)\/?#\/send\/([^/?#]+)\/([A-Za-z0-9_-]+)\/?$/);
  if (!m) return null;
  try {
    return { server: m[1], accessId: m[2], material: fromB64Url(m[3]) };
  } catch {
    return null;
  }
}

export async function decryptSend(raw: RawSend, userKey: SymKey): Promise<SendView> {
  let error = false;
  const soft = <T>(p: Promise<T>, fallback: T) => p.catch(() => ((error = true), fallback));
  const material = await decryptBytes(raw.key, userKey);
  const key = await sendKey(material);
  const [name, notes, text, fileName] = await Promise.all([
    soft(decryptString(raw.name, key), "⚠ Couldn't decrypt"),
    soft(decryptOpt(raw.notes, key), null),
    raw.text ? soft(decryptOpt(raw.text.text, key), null) : Promise.resolve(null),
    raw.file ? soft(decryptOpt(raw.file.fileName, key), null) : Promise.resolve(null),
  ]);
  return {
    id: raw.id,
    accessId: raw.accessId,
    type: raw.type === SendType.File ? SendType.File : SendType.Text,
    name,
    notes,
    material: toB64Url(material),
    text: raw.text ? { text: text ?? "", hidden: !!raw.text.hidden } : null,
    file: raw.file ? { id: raw.file.id ?? "", fileName: fileName ?? "file", size: Number(raw.file.size ?? 0), sizeName: raw.file.sizeName ?? "" } : null,
    maxAccessCount: raw.maxAccessCount ?? null,
    accessCount: raw.accessCount ?? 0,
    hasPassword: !!raw.password,
    disabled: !!raw.disabled,
    hideEmail: !!raw.hideEmail,
    revisionDate: raw.revisionDate ?? null,
    expirationDate: raw.expirationDate ?? null,
    deletionDate: raw.deletionDate,
    error: error || undefined,
  };
}

/**
 * The request body for POST /sends, PUT /sends/{id} and POST /sends/file/v2. `password`: a new
 * password, or null to leave it as it is (removing one is its own request).
 */
export async function encryptSend(d: SendDraft, userKey: SymKey, password: string | null = null): Promise<{ body: Record<string, unknown>; key: SymKey; material: Uint8Array<ArrayBuffer> }> {
  const material = d.material ? fromB64Url(d.material) : newSendMaterial();
  const key = await sendKey(material);
  const body: Record<string, unknown> = {
    type: d.type,
    key: await encryptBytes(material, userKey),
    name: await encryptString(d.name, key),
    notes: await encryptOpt(d.notes, key),
    text: d.type === SendType.Text ? { text: await encryptString(d.text?.text ?? "", key), hidden: !!d.text?.hidden } : null,
    file: d.type === SendType.File && d.fileName ? { fileName: await encryptString(d.fileName, key) } : null,
    maxAccessCount: d.maxAccessCount,
    expirationDate: d.expirationDate,
    deletionDate: d.deletionDate,
    disabled: d.disabled,
    hideEmail: d.hideEmail,
    password: password ? await sendPasswordHash(password, material) : null,
  };
  return { body, key, material };
}

/** Days from now as an ISO date (the editor's deletion and expiration choices). */
export function inDays(days: number, now = Date.now()): string {
  return new Date(now + days * 86_400_000).toISOString();
}

/** "Deletes in 3 days", "Expired", "Disabled": whether a Send can be opened now, and for how long. */
export function sendStatus(s: SendView, now = Date.now()): { open: boolean; label: string } {
  const left = (iso: string) => {
    const ms = Date.parse(iso) - now;
    const h = Math.round(ms / 3_600_000);
    return h < 1 ? "less than an hour" : h < 48 ? `${h} ${h === 1 ? "hour" : "hours"}` : `${Math.round(h / 24)} days`;
  };
  if (s.disabled) return { open: false, label: "Disabled" };
  if (Date.parse(s.deletionDate) <= now) return { open: false, label: "Pending deletion" };
  if (s.expirationDate && Date.parse(s.expirationDate) <= now) return { open: false, label: "Expired" };
  if (s.maxAccessCount != null && s.accessCount >= s.maxAccessCount) return { open: false, label: "Maximum views reached" };
  if (s.expirationDate && Date.parse(s.expirationDate) < Date.parse(s.deletionDate)) return { open: true, label: `Expires in ${left(s.expirationDate)}` };
  return { open: true, label: `Deletes in ${left(s.deletionDate)}` };
}

/** What a recipient sees: POST /api/sends/access (with a send-access token) decrypted with the link's material. */
export async function decryptSendAccess(raw: { type: number; name: string; text?: { text?: string | null; hidden?: boolean } | null; file?: { id?: string; fileName?: string | null; size?: number | string; sizeName?: string } | null; expirationDate?: string | null; creatorIdentifier?: string | null }, material: Uint8Array) {
  const key = await sendKey(material);
  return {
    type: raw.type === SendType.File ? SendType.File : SendType.Text,
    name: await decryptString(raw.name, key),
    text: raw.text ? { text: (await decryptOpt(raw.text.text, key)) ?? "", hidden: !!raw.text.hidden } : null,
    file: raw.file ? { id: raw.file.id ?? "", fileName: (await decryptOpt(raw.file.fileName, key)) ?? "file", size: Number(raw.file.size ?? 0) } : null,
    expirationDate: raw.expirationDate ?? null,
    creator: raw.creatorIdentifier ?? null,
    key,
  };
}
