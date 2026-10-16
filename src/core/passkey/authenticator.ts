// The authenticator half of a passkey provider: ES256 keys stored the way Bitwarden stores them
// (`login.fido2Credentials`: PKCS#8 key as base64url, GUID credential id), so passkeys made here
// work in the official apps and Keyguard, and theirs work here.
import type { Fido2View } from "../vault/types.ts";
import { sha256 } from "../crypto/primitives.ts";
import { concat, fromB64Url, fromHex, toB64Url, toHex } from "../util/bytes.ts";
import { encode } from "./cbor.ts";

/** Bitwarden's AAGUID: relying parties show the passkey as coming from Bitwarden. */
export const AAGUID = fromHex("d548826e79b4db40a3d811116f7e8349");

export const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 } as const;

const EC = { name: "ECDSA", namedCurve: "P-256" } as const;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Stored credential id → the bytes a relying party sees. Bitwarden stores a GUID, or
 * "b64.<base64url>" for ids of other lengths (imported passkeys). */
export function credentialIdBytes(id: string): Uint8Array | null {
  if (GUID.test(id)) return fromHex(id.replace(/-/g, ""));
  if (id.startsWith("b64.")) {
    try {
      return fromB64Url(id.slice(4));
    } catch {
      return null;
    }
  }
  return null;
}

export function credentialIdString(raw: Uint8Array): string {
  if (raw.length !== 16) return "b64." + toB64Url(raw);
  const h = toHex(raw);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

const u16 = (n: number) => Uint8Array.of(n >> 8, n & 0xff);
const u32 = (n: number) => Uint8Array.of(n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);

export function coseKeyES256(x: Uint8Array, y: Uint8Array): Uint8Array {
  // kty EC2, alg ES256, crv P-256, x, y (canonical key order).
  return encode(new Map<number, any>([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
}

export async function authenticatorData(rpId: string, flags: number, counter: number, attested?: { rawId: Uint8Array; cose: Uint8Array }): Promise<Uint8Array> {
  const parts: Uint8Array[] = [await sha256(rpId), Uint8Array.of(flags), u32(counter)];
  if (attested) parts.push(AAGUID, u16(attested.rawId.length), attested.rawId, attested.cose);
  return concat(...parts);
}

/** WebCrypto's raw r‖s ECDSA signature → the DER form WebAuthn uses. */
export function derSignature(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b.subarray(i);
    return v[0] & 0x80 ? concat(Uint8Array.of(0x02, v.length + 1, 0), v) : concat(Uint8Array.of(0x02, v.length), v);
  };
  const h = raw.length / 2;
  const body = concat(int(raw.subarray(0, h)), int(raw.subarray(h)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

export interface PublicKeyInfo {
  x: Uint8Array;
  y: Uint8Array;
  spki: Uint8Array;
  cose: Uint8Array;
}

async function publicOf(pair: { publicKey: CryptoKey }): Promise<PublicKeyInfo> {
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const x = fromB64Url(jwk.x!);
  const y = fromB64Url(jwk.y!);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  return { x, y, spki, cose: coseKeyES256(x, y) };
}

/** Public key of a stored passkey (its private JWK carries x and y). */
export async function publicKeyOf(f: Fido2View): Promise<PublicKeyInfo> {
  const priv = await crypto.subtle.importKey("pkcs8", fromB64Url(f.keyValue), EC, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  const publicKey = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true }, EC, true, ["verify"]);
  return publicOf({ publicKey });
}

export interface NewPasskey {
  fido2: Fido2View;
  rawId: Uint8Array;
  pub: PublicKeyInfo;
}

export async function createPasskey(p: { rpId: string; rpName: string | null; userHandle: Uint8Array; userName: string | null; userDisplayName: string | null; discoverable: boolean }): Promise<NewPasskey> {
  if (p.userHandle.length < 1 || p.userHandle.length > 64) throw new TypeError("user.id must be 1 to 64 bytes");
  const pair = (await crypto.subtle.generateKey(EC, true, ["sign", "verify"])) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const id = crypto.randomUUID();
  const fido2: Fido2View = {
    credentialId: id,
    keyType: "public-key",
    keyAlgorithm: "ECDSA",
    keyCurve: "P-256",
    keyValue: toB64Url(pkcs8),
    rpId: p.rpId,
    userHandle: toB64Url(p.userHandle),
    userName: p.userName,
    counter: 0,
    rpName: p.rpName,
    userDisplayName: p.userDisplayName,
    discoverable: p.discoverable,
    creationDate: new Date().toISOString(),
  };
  pkcs8.fill(0);
  return { fido2, rawId: credentialIdBytes(id)!, pub: await publicOf(pair) };
}

/** attestationObject for a new passkey ("none" attestation, as Bitwarden sends). */
export async function attest(k: NewPasskey, uv: boolean): Promise<{ authenticatorData: Uint8Array; attestationObject: Uint8Array }> {
  const flags = FLAG.UP | (uv ? FLAG.UV : 0) | FLAG.BE | FLAG.BS | FLAG.AT;
  const ad = await authenticatorData(k.fido2.rpId, flags, k.fido2.counter, { rawId: k.rawId, cose: k.pub.cose });
  const attestationObject = encode(new Map<string, any>([["fmt", "none"], ["attStmt", new Map()], ["authData", ad]]));
  return { authenticatorData: ad, attestationObject };
}

/** Signs a login. Synced passkeys keep a zero counter; one that already counts keeps counting
 * (the caller saves `counter` back to the item). */
export async function assert(f: Fido2View, clientDataHash: Uint8Array, uv: boolean): Promise<{ authenticatorData: Uint8Array; signature: Uint8Array; userHandle: Uint8Array | null; counter: number }> {
  const counter = f.counter > 0 ? f.counter + 1 : 0;
  const ad = await authenticatorData(f.rpId, FLAG.UP | (uv ? FLAG.UV : 0) | FLAG.BE | FLAG.BS, counter);
  const key = await crypto.subtle.importKey("pkcs8", fromB64Url(f.keyValue), EC, false, ["sign"]);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, concat(ad, clientDataHash)));
  return { authenticatorData: ad, signature: derSignature(raw), userHandle: f.userHandle ? fromB64Url(f.userHandle) : null, counter };
}
