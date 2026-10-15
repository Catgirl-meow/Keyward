// Decrypt raw ciphers into views / summaries, and encrypt views back into request bodies.
// Every field is decrypted independently; failures are collected in `errors` instead of
// throwing, so one bad field (or item) never hides the rest of the vault.
import { decryptBytes, decryptString, encryptBytes, encryptString, EncStringError } from "../crypto/encstring.ts";
import { unwrapItemKey, wrapItemKey } from "../crypto/keys.ts";
import { sha256 } from "../crypto/primitives.ts";
import { SymKey } from "../crypto/symkey.ts";
import { equalBytes, toB64 } from "../util/bytes.ts";
import {
  CARD_FIELDS, CipherType, IDENTITY_FIELDS,
  type CipherView, type Fido2View, type FieldView, type LoginView, type RawCipher, type RawUri, type Summary, type UriView, type UriMatch
} from "./types.ts";

export interface KeyRing {
  user: SymKey;
  orgs: Map<string, SymKey>;
}

export function parentKey(raw: { organizationId?: string | null }, ring: KeyRing): SymKey {
  if (raw.organizationId) {
    const k = ring.orgs.get(raw.organizationId);
    if (!k) throw new EncStringError("organization key not available");
    return k;
  }
  return ring.user;
}

export async function itemKey(raw: RawCipher, ring: KeyRing): Promise<SymKey> {
  const parent = parentKey(raw, ring);
  return raw.key ? unwrapItemKey(raw.key, parent) : parent;
}

class Dec {
  errors: string[] = [];
  readonly key: SymKey;
  constructor(key: SymKey) {
    this.key = key;
  }
  async s(v: string | null | undefined, what: string): Promise<string | null> {
    if (v == null || v === "") return null;
    try {
      return await decryptString(v, this.key);
    } catch (e) {
      this.errors.push(`${what}: ${(e as Error).message}`);
      return null;
    }
  }
}

async function decryptUris(d: Dec, uris: RawUri[] | null | undefined): Promise<UriView[]> {
  const out: UriView[] = [];
  for (const [i, u] of (uris ?? []).entries()) {
    const uri = await d.s(u?.uri, `uri ${i}`);
    if (uri == null) continue;
    if (u.uriChecksum) {
      // Official clients drop URIs whose checksum does not match (protects against a server
      // swapping a URI to phish an autofill). Same here.
      const want = await d.s(u.uriChecksum, `uri ${i} checksum`);
      if (want && want !== toB64(await sha256(uri))) {
        d.errors.push(`uri ${i}: checksum mismatch`);
        continue;
      }
    }
    out.push({ uri, match: (u.match ?? null) as UriMatch | null });
  }
  return out;
}

async function decryptFido2(d: Dec, list: NonNullable<RawCipher["login"]>["fido2Credentials"]): Promise<Fido2View[]> {
  const out: Fido2View[] = [];
  for (const [i, f] of (list ?? []).entries()) {
    const p = `passkey ${i}`;
    const [credentialId, keyType, keyAlgorithm, keyCurve, keyValue, rpId, userHandle, userName, counter, rpName, userDisplayName, discoverable] =
      await Promise.all([
        d.s(f.credentialId, p), d.s(f.keyType, p), d.s(f.keyAlgorithm, p), d.s(f.keyCurve, p), d.s(f.keyValue, p), d.s(f.rpId, p),
        d.s(f.userHandle, p), d.s(f.userName, p), d.s(f.counter, p), d.s(f.rpName, p), d.s(f.userDisplayName, p), d.s(f.discoverable, p),
      ]);
    if (!credentialId || !keyValue || !rpId) continue;
    out.push({
      credentialId, keyType: keyType ?? "public-key", keyAlgorithm: keyAlgorithm ?? "ECDSA", keyCurve: keyCurve ?? "P-256",
      keyValue, rpId, userHandle, userName, counter: Number(counter ?? 0) || 0, rpName, userDisplayName,
      discoverable: discoverable === "true", creationDate: f.creationDate ?? new Date(0).toISOString(),
    });
  }
  return out;
}

export async function decryptCipher(raw: RawCipher, ring: KeyRing): Promise<CipherView> {
  let key: SymKey;
  try {
    key = await itemKey(raw, ring);
  } catch (e) {
    return brokenView(raw, `item key: ${(e as Error).message}`);
  }
  const d = new Dec(key);
  const name = (await d.s(raw.name, "name")) ?? "";
  const notes = await d.s(raw.notes, "notes");

  let login: LoginView | null = null;
  if (raw.type === CipherType.Login && raw.login) {
    const l = raw.login;
    const [username, password, totp, uris, fido2] = await Promise.all([
      d.s(l.username, "username"), d.s(l.password, "password"), d.s(l.totp, "totp"), decryptUris(d, l.uris), decryptFido2(d, l.fido2Credentials),
    ]);
    login = {
      username, password, totp, uris, fido2Credentials: fido2,
      passwordRevisionDate: l.passwordRevisionDate ?? null, autofillOnPageLoad: l.autofillOnPageLoad ?? null,
    };
  }
  let card: CipherView["card"] = null;
  if (raw.type === CipherType.Card && raw.card) {
    const vals = await Promise.all(CARD_FIELDS.map((f) => d.s(raw.card![f], f)));
    card = Object.fromEntries(CARD_FIELDS.map((f, i) => [f, vals[i]])) as any;
  }
  let identity: CipherView["identity"] = null;
  if (raw.type === CipherType.Identity && raw.identity) {
    const vals = await Promise.all(IDENTITY_FIELDS.map((f) => d.s(raw.identity![f], f)));
    identity = Object.fromEntries(IDENTITY_FIELDS.map((f, i) => [f, vals[i]])) as any;
  }
  let sshKey: CipherView["sshKey"] = null;
  if (raw.type === CipherType.SshKey && raw.sshKey) {
    const [privateKey, publicKey, keyFingerprint] = await Promise.all([
      d.s(raw.sshKey.privateKey, "ssh private key"), d.s(raw.sshKey.publicKey, "ssh public key"), d.s(raw.sshKey.keyFingerprint, "ssh fingerprint"),
    ]);
    sshKey = { privateKey, publicKey, keyFingerprint };
  }
  const fields: FieldView[] = await Promise.all(
    (raw.fields ?? []).map(async (f, i) => ({
      type: (f.type ?? 0) as FieldView["type"],
      name: await d.s(f.name, `field ${i} name`),
      value: await d.s(f.value, `field ${i} value`),
      linkedId: f.linkedId ?? null,
    })),
  );
  const passwordHistory = (
    await Promise.all(
      (raw.passwordHistory ?? []).map(async (h, i) => ({ password: (await d.s(h.password, `history ${i}`)) ?? "", lastUsedDate: h.lastUsedDate ?? "" })),
    )
  ).filter((h) => h.password);
  const attachments = await Promise.all(
    (raw.attachments ?? []).map(async (a, i) => ({
      id: a.id,
      fileName: await d.s(a.fileName, `attachment ${i} name`),
      size: Number(a.size ?? 0) || 0,
      sizeName: a.sizeName ?? null,
      url: a.url ?? null,
      key: a.key ?? null,
    })),
  );

  return {
    id: raw.id,
    type: raw.type as CipherType,
    name,
    notes,
    favorite: !!raw.favorite,
    reprompt: raw.reprompt ?? 0,
    folderId: raw.folderId ?? null,
    organizationId: raw.organizationId ?? null,
    collectionIds: raw.collectionIds ?? [],
    creationDate: raw.creationDate ?? null,
    revisionDate: raw.revisionDate ?? null,
    deletedDate: raw.deletedDate ?? null,
    archivedDate: raw.archivedDate ?? null,
    edit: raw.edit ?? true,
    viewPassword: raw.viewPassword ?? true,
    login, card, identity, sshKey, fields, passwordHistory, attachments,
    errors: d.errors,
    hasItemKey: !!raw.key,
  };
}

function brokenView(raw: RawCipher, err: string): CipherView {
  return {
    id: raw.id, type: (raw.type ?? 2) as CipherType, name: "⚠ Unreadable item", notes: null, favorite: !!raw.favorite, reprompt: 0,
    folderId: raw.folderId ?? null, organizationId: raw.organizationId ?? null, collectionIds: raw.collectionIds ?? [],
    creationDate: raw.creationDate ?? null, revisionDate: raw.revisionDate ?? null, deletedDate: raw.deletedDate ?? null,
    archivedDate: raw.archivedDate ?? null, edit: false, viewPassword: false, login: null, card: null, identity: null, sshKey: null,
    fields: [], passwordHistory: [], attachments: [], errors: [err], hasItemKey: !!raw.key,
  };
}

// ---------------- summaries ----------------

export function cardSubtitle(c: CipherView["card"]): string {
  if (!c) return "";
  const last4 = c.number ? c.number.replace(/\s+/g, "").slice(-4) : "";
  return [c.brand, last4 && `*${last4}`].filter(Boolean).join(", ");
}

export function identitySubtitle(i: CipherView["identity"]): string {
  if (!i) return "";
  return [i.firstName, i.lastName].filter(Boolean).join(" ") || i.email || i.username || "";
}

export function subtitleOf(v: CipherView): string {
  switch (v.type) {
    case CipherType.Login:
      return v.login?.username || v.login?.fido2Credentials[0]?.userName || "";
    case CipherType.Card:
      return cardSubtitle(v.card);
    case CipherType.Identity:
      return identitySubtitle(v.identity);
    case CipherType.SshKey:
      return v.sshKey?.keyFingerprint ?? "";
    default:
      return v.notes ? v.notes.slice(0, 80).replace(/\s+/g, " ") : "";
  }
}

export function summarize(v: CipherView): Summary {
  return {
    id: v.id,
    type: v.type,
    name: v.name,
    sub: subtitleOf(v),
    fav: v.favorite,
    folder: v.folderId,
    org: v.organizationId,
    cols: v.collectionIds,
    uris: v.login?.uris.map((u) => u.uri) ?? [],
    match: v.login?.uris.map((u) => u.match) ?? [],
    totp: !!v.login?.totp,
    pk: v.login?.fido2Credentials.map((f) => f.rpId) ?? [],
    rp: v.reprompt === 1,
    att: v.attachments.length > 0,
    del: v.deletedDate,
    arch: v.archivedDate,
    rev: v.revisionDate,
    created: v.creationDate,
    pwRev: v.login?.passwordRevisionDate ?? null,
    note: v.notes ? v.notes.slice(0, 160) : null,
    brand: v.card?.brand ?? null,
    err: v.errors.length ? v.errors.join("; ") : null,
  };
}

// ---------------- encryption (view → request body) ----------------

export interface EncryptOpts {
  /** Raw server object this view came from; unknown fields are preserved. */
  base?: RawCipher | null;
  /** Generate a per-item key for new items (official clients do this for servers ≥ 2024.2). */
  useItemKey?: boolean;
}

export async function encryptCipher(v: CipherView, ring: KeyRing, opts: EncryptOpts = {}): Promise<{ body: Record<string, any>; key: SymKey }> {
  const parent = parentKey({ organizationId: v.organizationId }, ring);
  let key: SymKey;
  let wrappedKey: string | null = null;
  const base = opts.base;
  const sameParent = base && (base.organizationId ?? null) === (v.organizationId ?? null);
  if (base?.key && sameParent) {
    wrappedKey = base.key;
    key = await unwrapItemKey(base.key, parent);
  } else if (base?.key || opts.useItemKey !== false) {
    // New item, or moving an item between personal vault and an organization: fresh item key.
    key = SymKey.random();
    wrappedKey = await wrapItemKey(key, parent);
  } else {
    key = parent;
  }
  const e = (s: string | null | undefined) => (s == null || s === "" ? Promise.resolve(null) : encryptString(s, key));

  const body: Record<string, any> = {
    type: v.type,
    folderId: v.folderId,
    organizationId: v.organizationId,
    name: await e(v.name || "—"),
    notes: await e(v.notes),
    favorite: v.favorite,
    reprompt: v.reprompt,
    key: wrappedKey,
    lastKnownRevisionDate: base?.revisionDate ?? null,
    archivedDate: v.archivedDate,
    login: null,
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
  };

  if (v.type === CipherType.Login && v.login) {
    const l = v.login;
    body.login = {
      username: await e(l.username),
      password: await e(l.password),
      passwordRevisionDate: l.passwordRevisionDate,
      totp: await e(l.totp),
      autofillOnPageLoad: l.autofillOnPageLoad,
      uris: await Promise.all(
        l.uris.filter((u) => u.uri.trim()).map(async (u) => ({
          uri: await e(u.uri),
          uriChecksum: await e(toB64(await sha256(u.uri))),
          match: u.match,
        })),
      ),
      fido2Credentials: await Promise.all(
        l.fido2Credentials.map(async (f) => ({
          credentialId: await e(f.credentialId),
          keyType: await e(f.keyType),
          keyAlgorithm: await e(f.keyAlgorithm),
          keyCurve: await e(f.keyCurve),
          keyValue: await e(f.keyValue),
          rpId: await e(f.rpId),
          userHandle: await e(f.userHandle),
          userName: await e(f.userName),
          counter: await e(String(f.counter)),
          rpName: await e(f.rpName),
          userDisplayName: await e(f.userDisplayName),
          discoverable: await e(String(f.discoverable)),
          creationDate: f.creationDate,
        })),
      ),
    };
  } else if (v.type === CipherType.Card && v.card) {
    body.card = Object.fromEntries(await Promise.all(CARD_FIELDS.map(async (f) => [f, await e(v.card![f])])));
  } else if (v.type === CipherType.Identity && v.identity) {
    body.identity = Object.fromEntries(await Promise.all(IDENTITY_FIELDS.map(async (f) => [f, await e(v.identity![f])])));
  } else if (v.type === CipherType.SshKey && v.sshKey) {
    body.sshKey = {
      privateKey: await e(v.sshKey.privateKey),
      publicKey: await e(v.sshKey.publicKey),
      keyFingerprint: await e(v.sshKey.keyFingerprint),
    };
  } else if (v.type === CipherType.SecureNote) {
    body.secureNote = { type: 0 };
  }

  body.fields = await Promise.all(v.fields.map(async (f) => ({ type: f.type, name: await e(f.name), value: await e(f.value), linkedId: f.linkedId })));
  body.passwordHistory = await Promise.all(
    v.passwordHistory.slice(0, 5).map(async (h) => ({ password: await e(h.password), lastUsedDate: h.lastUsedDate })),
  );

  // Attachments: re-wrap each attachment key when the item key changed.
  if (v.attachments.length && base) {
    const oldKey = await itemKey(base, ring).catch(() => null);
    const keyChanged = !!oldKey && !equalBytes(oldKey.raw, key.raw);
    const att2: Record<string, { fileName: string | null; key: string | null }> = {};
    for (const a of v.attachments) {
      const wrapped = a.key && keyChanged ? await encryptBytes(await decryptBytes(a.key, oldKey!), key) : a.key;
      att2[a.id] = { fileName: await e(a.fileName), key: wrapped };
    }
    body.attachments2 = att2;
  }

  if (base) {
    // Preserve fields we do not understand (future server features).
    for (const k of Object.keys(base)) {
      if (!(k in body) && !SERVER_ONLY.has(k)) body[k] = (base as any)[k];
    }
  }
  return { body, key };
}

const SERVER_ONLY = new Set([
  "id", "object", "edit", "viewPassword", "permissions", "organizationUseTotp", "revisionDate", "creationDate", "deletedDate",
  "attachments", "collectionIds", "data", "fields", "passwordHistory", "login", "card", "identity", "secureNote", "sshKey",
]);

export function emptyView(type: CipherType, init: Partial<CipherView> = {}): CipherView {
  return {
    id: "", type, name: "", notes: null, favorite: false, reprompt: 0, folderId: null, organizationId: null, collectionIds: [],
    creationDate: null, revisionDate: null, deletedDate: null, archivedDate: null, edit: true, viewPassword: true,
    login: type === CipherType.Login ? { username: null, password: null, passwordRevisionDate: null, totp: null, uris: [], autofillOnPageLoad: null, fido2Credentials: [] } : null,
    card: type === CipherType.Card ? { cardholderName: null, brand: null, number: null, expMonth: null, expYear: null, code: null } : null,
    identity: type === CipherType.Identity ? (Object.fromEntries(IDENTITY_FIELDS.map((f) => [f, null])) as any) : null,
    sshKey: type === CipherType.SshKey ? { privateKey: null, publicKey: null, keyFingerprint: null } : null,
    fields: [], passwordHistory: [], attachments: [], errors: [], hasItemKey: false,
    ...init,
  };
}
