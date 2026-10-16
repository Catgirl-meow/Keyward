// GPG key items, stored the way Keyguard stores them so either app opens the other's keys
// (keyguard.dev/docs/item-extras; Keyguard's BitwardenGpgKeyFieldCodec.kt): a secure note with
//   keyguard.gpg.private_key.armored   hidden field, the armored private key (if any)
//   keyguard.gpg.public_key.armored    text field, the armored public key
//   keyguard.gpg.fingerprint           text field, the primary key's fingerprint
// A key over 3,500 UTF-8 bytes would encrypt past the server's 5,000-character field limit, so it
// is split into "<name>.v1.part.1", "<name>.v1.part.2", … plus "<name>.v1.sha256" (lowercase hex
// SHA-256 of the whole value). A malformed group decodes to nothing and every field is kept as is.
import { sha256 } from "../crypto/primitives.ts";
import { toHex, utf8 } from "../util/bytes.ts";
import { CipherType, FieldType, type CipherView, type FieldView } from "../vault/types.ts";

export const GPG_FIELD = {
  privateKey: "keyguard.gpg.private_key.armored",
  publicKey: "keyguard.gpg.public_key.armored",
  fingerprint: "keyguard.gpg.fingerprint",
} as const;

export interface GpgKeyFields {
  privateKey: string | null;
  publicKey: string | null;
  fingerprint: string | null;
}

const CHUNK_BYTES = 3500;
const chunkPrefix = (name: string) => `${name}.v1.`;
const partPrefix = (name: string) => `${name}.v1.part.`;
const hashName = (name: string) => `${name}.v1.sha256`;
const CHUNKABLE = [GPG_FIELD.privateKey, GPG_FIELD.publicKey];

/** A field that belongs to the GPG representation (and not to the user's own custom fields). */
export function isGpgFieldName(name: string | null): boolean {
  if (!name) return false;
  return name === GPG_FIELD.privateKey || name === GPG_FIELD.publicKey || name === GPG_FIELD.fingerprint || CHUNKABLE.some((b) => name.startsWith(chunkPrefix(b)));
}

/** Cheap check for list summaries: a secure note carrying GPG fields. */
export function looksLikeGpgItem(v: Pick<CipherView, "type" | "fields">): boolean {
  return v.type === CipherType.SecureNote && v.fields.some((f) => isGpgFieldName(f.name));
}

const blank = (s: string | null | undefined) => !s || !s.trim();

/** The item's fields with the key written in: GPG fields first, then the user's own. */
export async function encodeGpgFields(key: GpgKeyFields, fields: FieldView[]): Promise<FieldView[]> {
  const rest = fields.filter((f) => !isGpgFieldName(f.name));
  if (blank(key.privateKey) && blank(key.publicKey) && blank(key.fingerprint)) return rest;
  const out: FieldView[] = [];
  const add = (name: string, value: string, type: FieldType) => out.push({ type, name, value, linkedId: null });
  for (const [name, value, type] of [
    [GPG_FIELD.privateKey, key.privateKey, FieldType.Hidden],
    [GPG_FIELD.publicKey, key.publicKey, FieldType.Text],
  ] as const) {
    if (blank(value)) continue;
    const bytes = utf8(value!);
    if (bytes.length <= CHUNK_BYTES) {
      add(name, value!, type);
      continue;
    }
    splitUtf8(bytes, CHUNK_BYTES).forEach((chunk, i) => add(`${partPrefix(name)}${i + 1}`, chunk, type));
    add(hashName(name), toHex(await sha256(bytes)), type);
  }
  if (!blank(key.fingerprint)) add(GPG_FIELD.fingerprint, key.fingerprint!, FieldType.Text);
  return [...out, ...rest];
}

/** Splits at most `max` bytes at a time, never inside a UTF-8 sequence. */
function splitUtf8(bytes: Uint8Array, max: number): string[] {
  const td = new TextDecoder();
  const out: string[] = [];
  for (let start = 0; start < bytes.length; ) {
    let end = Math.min(start + max, bytes.length);
    while (end < bytes.length && (bytes[end] & 0xc0) === 0x80) end--;
    out.push(td.decode(bytes.subarray(start, end)));
    start = end;
  }
  return out;
}

/**
 * The key and the item's other fields, or null when the item carries no (valid) GPG key; then
 * its fields are shown as ordinary custom fields, untouched.
 */
export async function decodeGpgFields(fields: FieldView[]): Promise<{ key: GpgKeyFields; rest: FieldView[] } | null> {
  if (!fields.some((f) => isGpgFieldName(f.name))) return null;
  const used = new Set<number>();
  const privateKey = await decodeOne(fields, GPG_FIELD.privateKey, FieldType.Hidden, used);
  const publicKey = await decodeOne(fields, GPG_FIELD.publicKey, FieldType.Text, used);
  const fingerprint = await decodeOne(fields, GPG_FIELD.fingerprint, null, used);
  if (privateKey === undefined || publicKey === undefined || fingerprint === undefined) return null;
  if (blank(privateKey) && blank(publicKey) && blank(fingerprint)) return null;
  return { key: { privateKey, publicKey, fingerprint }, rest: fields.filter((_, i) => !used.has(i)) };
}

/** One value: null when absent, undefined when its chunk group is malformed. */
async function decodeOne(fields: FieldView[], name: string, chunkType: FieldType | null, used: Set<number>): Promise<string | null | undefined> {
  const plain = fields.flatMap((f, i) => (f.name === name && f.linkedId == null && (f.type === FieldType.Text || f.type === FieldType.Hidden) ? [i] : []));
  const chunks = chunkType == null ? [] : fields.flatMap((f, i) => (f.name?.startsWith(chunkPrefix(name)) ? [i] : []));
  if (!chunks.length) {
    plain.forEach((i) => used.add(i));
    return plain.map((i) => fields[i].value).find((v) => v != null) ?? null;
  }
  const hashes = chunks.filter((i) => fields[i].name === hashName(name));
  if (hashes.length !== 1) return undefined;
  const h = fields[hashes[0]];
  if (!/^[0-9a-f]{64}$/.test(h.value ?? "") || h.type !== chunkType || h.linkedId != null) return undefined;
  const parts: [number, string][] = [];
  for (const i of chunks) {
    if (i === hashes[0]) continue;
    const f = fields[i];
    const raw = f.name!.startsWith(partPrefix(name)) ? f.name!.slice(partPrefix(name).length) : "";
    const n = Number(raw);
    // Canonical positive integers only: no signs, leading zeros or other forms.
    if (f.type !== chunkType || f.linkedId != null || !f.value || utf8(f.value).length > CHUNK_BYTES || !(n > 0) || String(n) !== raw) return undefined;
    parts.push([n, f.value]);
  }
  parts.sort((a, b) => a[0] - b[0]);
  if (!parts.length || parts.some(([n], k) => n !== k + 1)) return undefined;
  const value = parts.map(([, s]) => s).join("");
  if (toHex(await sha256(utf8(value))) !== h.value) return undefined;
  if (plain.some((i) => fields[i].value !== value)) return undefined;
  [...plain, ...chunks].forEach((i) => used.add(i));
  return value;
}
