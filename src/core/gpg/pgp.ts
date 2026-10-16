// OpenPGP for GPG key items and the GPG tools, on OpenPGP.js (pages load this lazily; the build
// swaps in its lightweight bundle). Keys are v4 Ed25519 + Cv25519 by default, what gpg itself
// makes: gpg 2.5 refuses the newer RFC 9580 Ed25519/X25519 algorithms.
import * as openpgp from "openpgp";

export type KeyUse = "certify" | "sign" | "encrypt" | "auth";

export interface GpgSubkeyInfo {
  keyId: string;
  fingerprint: string;
  algorithm: string;
  created: string;
  /** null: never expires */
  expires: string | null;
  uses: KeyUse[];
  revoked: boolean;
}

export interface GpgKeyInfo extends GpgSubkeyInfo {
  userIds: string[];
  isPrivate: boolean;
  /** a private key protected by its own passphrase */
  locked: boolean;
  subkeys: GpgSubkeyInfo[];
  /** the armored public key (for a private key: its public part) */
  publicKey: string;
}

export interface NewKeyOptions {
  name: string;
  email: string;
  /** null: never */
  expiresInDays: number | null;
  type?: "ecc" | "rsa";
}

/** The fingerprint as gpg prints it: uppercase hex. */
export const fingerprintOf = (k: openpgp.Key | openpgp.Subkey) => k.getFingerprint().toUpperCase();
const keyIdOf = (k: openpgp.Key | openpgp.Subkey) => k.getKeyID().toHex().toUpperCase();

/** Groups of four, as gpg shows fingerprints. */
export const spacedFingerprint = (fp: string) => fp.replace(/\s/g, "").toUpperCase().replace(/(.{4})(?=.)/g, "$1 ");

function algorithmLabel(a: openpgp.AlgorithmInfo): string {
  const bits = a.bits ? ` ${a.bits}` : "";
  switch (a.algorithm) {
    case "eddsaLegacy":
    case "ed25519":
      return "Ed25519";
    case "ed448":
      return "Ed448";
    case "x25519":
      return "X25519";
    case "x448":
      return "X448";
    case "ecdh":
    case "ecdsa": {
      const curve = a.curve === "curve25519Legacy" ? "Cv25519" : a.curve?.replace(/^nistP/, "P-") ?? "";
      return a.curve === "curve25519Legacy" ? curve : `${a.algorithm.toUpperCase()} ${curve}`;
    }
    case "rsaEncryptSign":
    case "rsaSign":
    case "rsaEncrypt":
      return `RSA${bits}`;
    case "dsa":
      return `DSA${bits}`;
    case "elgamal":
      return `ElGamal${bits}`;
    default:
      return String(a.algorithm);
  }
}

function usesOf(flags: Uint8Array | null | undefined): KeyUse[] {
  const f = flags?.[0] ?? 0;
  const out: KeyUse[] = [];
  if (f & 0x01) out.push("certify");
  if (f & 0x02) out.push("sign");
  if (f & 0x0c) out.push("encrypt");
  if (f & 0x20) out.push("auth");
  return out;
}

const latest = (sigs: openpgp.SignaturePacket[]) => [...sigs].sort((a, b) => (b.created?.getTime() ?? 0) - (a.created?.getTime() ?? 0))[0];
const isoOrNever = (d: Date | typeof Infinity | null) => (d instanceof Date ? d.toISOString() : null);

async function primaryFlags(key: openpgp.Key): Promise<Uint8Array | null> {
  try {
    return (await key.getPrimaryUser()).selfCertification.keyFlags;
  } catch {
    // Expired or otherwise unusable: still show what the newest self-signature says.
    return latest(key.users.flatMap((u) => u.selfCertifications))?.keyFlags ?? null;
  }
}

async function safe<T>(p: Promise<T>, fallback: T): Promise<T> {
  try {
    return await p;
  } catch {
    return fallback;
  }
}

/** Reads one armored (or binary) public or private key. */
export async function readGpgKey(armored: string): Promise<openpgp.Key> {
  const text = armored.trim();
  if (!text) throw new Error("Paste a key");
  try {
    return await openpgp.readKey({ armoredKey: text });
  } catch (e) {
    throw new Error(`Not an OpenPGP key: ${(e as Error).message}`);
  }
}

/**
 * A key from a file or pasted text: armored or binary, public or private. A keyring with more
 * than one key is refused, since a GPG key item holds one.
 */
export async function readGpgKeyData(data: string | Uint8Array): Promise<openpgp.Key> {
  const text = typeof data === "string" ? data : new TextDecoder().decode(data);
  let keys: openpgp.Key[];
  try {
    keys = text.includes("-----BEGIN PGP")
      ? await openpgp.readKeys({ armoredKeys: text.trim() })
      : typeof data === "string"
        ? []
        : await openpgp.readKeys({ binaryKeys: data });
  } catch (e) {
    throw new Error(`Not an OpenPGP key: ${(e as Error).message}`);
  }
  if (!keys.length) throw new Error(text.trim() ? "Not an OpenPGP key" : "Paste a key");
  if (keys.length > 1) throw new Error(`This holds ${keys.length} keys; import them one at a time`);
  return keys[0];
}

/** What a GPG key item stores for `key`. */
export function keyFields(key: openpgp.Key): { privateKey: string | null; publicKey: string; fingerprint: string } {
  return { privateKey: key.isPrivate() ? key.armor() : null, publicKey: key.toPublic().armor(), fingerprint: fingerprintOf(key) };
}

export async function describeKey(key: openpgp.Key): Promise<GpgKeyInfo> {
  const subkeys = await Promise.all(
    key.subkeys.map(async (s): Promise<GpgSubkeyInfo> => {
      const binding = latest(s.bindingSignatures);
      return {
        keyId: keyIdOf(s),
        fingerprint: fingerprintOf(s),
        algorithm: algorithmLabel(s.getAlgorithmInfo()),
        created: s.getCreationTime().toISOString(),
        expires: isoOrNever(await safe(s.getExpirationTime(), null)),
        uses: usesOf(binding?.keyFlags),
        revoked: binding ? await safe(s.isRevoked(binding, s.keyPacket), false) : false,
      };
    }),
  );
  const isPrivate = key.isPrivate();
  return {
    keyId: keyIdOf(key),
    fingerprint: fingerprintOf(key),
    algorithm: algorithmLabel(key.getAlgorithmInfo()),
    created: key.getCreationTime().toISOString(),
    expires: isoOrNever(await safe(key.getExpirationTime(), null)),
    uses: usesOf(await primaryFlags(key)),
    revoked: await safe(key.isRevoked(), false),
    userIds: key.getUserIDs(),
    isPrivate,
    locked: isPrivate && !(key as openpgp.PrivateKey).isDecrypted(),
    subkeys,
    publicKey: key.toPublic().armor(),
  };
}

/** A new key pair, unprotected: the vault item that keeps it is what protects it. */
export async function generateGpgKey(o: NewKeyOptions): Promise<{ privateKey: string; publicKey: string; fingerprint: string }> {
  const userID = { name: o.name.trim() || undefined, email: o.email.trim() || undefined };
  if (!userID.name && !userID.email) throw new Error("Enter a name or an email");
  const { privateKey, publicKey } = await openpgp.generateKey({
    ...(o.type === "rsa" ? { type: "rsa" as const, rsaBits: 4096 } : { type: "ecc" as const, curve: "curve25519Legacy" as const }),
    userIDs: [userID],
    keyExpirationTime: o.expiresInDays ? o.expiresInDays * 86400 : 0,
    format: "armored",
  });
  return { privateKey, publicKey, fingerprint: fingerprintOf(await openpgp.readKey({ armoredKey: publicKey })) };
}

/** The private key, ready to use: decrypted with `passphrase` when it has one. */
export async function unlockKey(armored: string, passphrase?: string): Promise<openpgp.PrivateKey> {
  const key = await openpgp.readPrivateKey({ armoredKey: armored });
  if (key.isDecrypted()) return key;
  if (!passphrase) throw new PassphraseNeeded(fingerprintOf(key));
  try {
    return await openpgp.decryptKey({ privateKey: key, passphrase });
  } catch {
    throw new PassphraseNeeded(fingerprintOf(key), true);
  }
}

export class PassphraseNeeded extends Error {
  fingerprint: string;
  wrong: boolean;
  constructor(fingerprint: string, wrong = false) {
    super(wrong ? "Wrong passphrase for this key" : "This key is protected by a passphrase");
    this.fingerprint = fingerprint;
    this.wrong = wrong;
  }
}

/** Signs text: a cleartext-signed message, or a detached armored signature. */
export async function signText(text: string, key: openpgp.PrivateKey, detached = false): Promise<string> {
  if (detached) return openpgp.sign({ message: await openpgp.createMessage({ text }), signingKeys: key, detached: true });
  return openpgp.sign({ message: await openpgp.createCleartextMessage({ text }), signingKeys: key });
}

export interface SignatureCheck {
  /** long key ID of the signing key */
  keyId: string;
  valid: boolean;
  /** the vault key that made it, when known */
  signer: { fingerprint: string; userId: string } | null;
  error: string | null;
  created: string | null;
}

export interface Verified {
  text: string;
  signatures: SignatureCheck[];
}

type VerificationResult = Awaited<ReturnType<typeof openpgp.verify>>["signatures"][number];

async function checkSignatures(results: VerificationResult[], keys: openpgp.Key[]): Promise<SignatureCheck[]> {
  return Promise.all(
    results.map(async (r) => {
      const keyId = r.keyID.toHex().toUpperCase();
      const owner = keys.find((k) => k.getKeys(r.keyID).length > 0) ?? null;
      let valid = false;
      let error: string | null = null;
      try {
        valid = await r.verified;
      } catch (e) {
        error = owner ? (e as Error).message.replace(/^Error verifying signature: /, "") : "No public key for this signature";
      }
      const created = await r.signature.then((sig: openpgp.Signature) => sig.packets[0]?.created?.toISOString() ?? null).catch(() => null);
      return { keyId, valid, signer: owner ? { fingerprint: fingerprintOf(owner), userId: owner.getUserIDs()[0] ?? "" } : null, error, created };
    }),
  );
}

/** Verifies a cleartext-signed or signed message, or `text` against a detached signature. */
export async function verifyText(signed: string, keys: openpgp.Key[], detachedFor?: string): Promise<Verified> {
  const verificationKeys = keys.map((k) => k.toPublic());
  if (detachedFor != null) {
    const signature = await openpgp.readSignature({ armoredSignature: signed.trim() });
    const r = await openpgp.verify({ message: await openpgp.createMessage({ text: detachedFor }), signature, verificationKeys, expectSigned: false });
    return { text: detachedFor, signatures: await checkSignatures(r.signatures, keys) };
  }
  const body = signed.trim();
  if (body.startsWith("-----BEGIN PGP SIGNED MESSAGE-----")) {
    const message = await openpgp.readCleartextMessage({ cleartextMessage: body });
    const r = await openpgp.verify({ message, verificationKeys, expectSigned: false });
    return { text: String(r.data), signatures: await checkSignatures(r.signatures, keys) };
  }
  const message = await openpgp.readMessage({ armoredMessage: body });
  const r = await openpgp.verify({ message, verificationKeys, expectSigned: false });
  return { text: String(r.data), signatures: await checkSignatures(r.signatures, keys) };
}

/** Encrypts text to `recipients` (public keys), optionally signed. */
export async function encryptText(text: string, recipients: openpgp.Key[], signWith?: openpgp.PrivateKey): Promise<string> {
  if (!recipients.length) throw new Error("Choose at least one recipient");
  return openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys: recipients.map((k) => k.toPublic()), signingKeys: signWith });
}

/** Long key IDs a message is encrypted to (all zeros: a hidden recipient). */
export async function recipientsOf(armored: string): Promise<string[]> {
  const message = await openpgp.readMessage({ armoredMessage: armored.trim() });
  return message.getEncryptionKeyIDs().map((id) => id.toHex().toUpperCase());
}

/** Decrypts with whichever of `keys` it was encrypted to; signatures checked against `verifyWith`. */
export async function decryptText(armored: string, keys: openpgp.PrivateKey[], verifyWith: openpgp.Key[]): Promise<Verified> {
  const message = await openpgp.readMessage({ armoredMessage: armored.trim() });
  const ids = message.getEncryptionKeyIDs();
  const usable = keys.filter((k) => ids.some((id) => isWildcardId(id.toHex()) || k.getKeys(id).length > 0));
  if (!usable.length) throw new Error("None of your GPG keys can open this message");
  const r = await openpgp.decrypt({ message, decryptionKeys: usable, verificationKeys: verifyWith.map((k) => k.toPublic()), expectSigned: false });
  return { text: String(r.data), signatures: await checkSignatures(r.signatures, verifyWith) };
}

export const isWildcardId = (id: string) => /^0+$/.test(id);
