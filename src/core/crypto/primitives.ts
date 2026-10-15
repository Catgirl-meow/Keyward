// Thin WebCrypto wrappers. Everything Bitwarden needs except Argon2id is native here,
// which is the main reason Keyward does not ship a 7.5 MB WASM SDK.
import { concat, own, utf8 } from "../util/bytes.ts";

const subtle = globalThis.crypto.subtle;
type Bytes = Uint8Array<ArrayBuffer>;

export async function sha256(data: Uint8Array | string): Promise<Bytes> {
  const d = typeof data === "string" ? utf8(data) : own(data);
  return new Uint8Array(await subtle.digest("SHA-256", d));
}

export async function sha1(data: Uint8Array | string): Promise<Bytes> {
  const d = typeof data === "string" ? utf8(data) : own(data);
  return new Uint8Array(await subtle.digest("SHA-1", d));
}

export async function pbkdf2Sha256(password: Uint8Array, salt: Uint8Array, iterations: number, len = 32): Promise<Bytes> {
  const base = await subtle.importKey("raw", own(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: own(salt), iterations }, base, len * 8);
  return new Uint8Array(bits);
}

export async function importHmacKey(raw: Uint8Array, hash: "SHA-256" | "SHA-1" | "SHA-512" = "SHA-256"): Promise<CryptoKey> {
  return subtle.importKey("raw", own(raw), { name: "HMAC", hash }, false, ["sign", "verify"]);
}

export async function hmac(key: CryptoKey, data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.sign("HMAC", key, own(data)));
}

export async function hmacSha256(rawKey: Uint8Array, data: Uint8Array): Promise<Bytes> {
  return hmac(await importHmacKey(rawKey), data);
}

/** RFC 5869 HKDF-Expand with SHA-256 (Bitwarden uses Expand only for key stretching). */
export async function hkdfExpand(prk: Uint8Array, info: string | Uint8Array, len: number): Promise<Bytes> {
  const infoB = typeof info === "string" ? utf8(info) : info;
  const key = await importHmacKey(prk);
  const out = new Uint8Array(len);
  let prev: Uint8Array = new Uint8Array(0);
  let off = 0;
  for (let i = 1; off < len; i++) {
    prev = await hmac(key, concat(prev, infoB, new Uint8Array([i])));
    const take = Math.min(prev.length, len - off);
    out.set(prev.subarray(0, take), off);
    off += take;
  }
  return out;
}

/** Full HKDF (extract + expand) with SHA-256, used for Send keys and local cache keys. */
export async function hkdf(ikm: Uint8Array, salt: string | Uint8Array, info: string | Uint8Array, len: number): Promise<Bytes> {
  const base = await subtle.importKey("raw", own(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: typeof salt === "string" ? utf8(salt) : own(salt),
      info: typeof info === "string" ? utf8(info) : own(info),
    },
    base,
    len * 8,
  );
  return new Uint8Array(bits);
}

export async function importAesCbc(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", own(raw), "AES-CBC", false, ["encrypt", "decrypt"]);
}

export async function aesCbcDecrypt(key: CryptoKey, iv: Uint8Array, data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv: own(iv) }, key, own(data)));
}

export async function aesCbcEncrypt(key: CryptoKey, iv: Uint8Array, data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv: own(iv) }, key, own(data)));
}

export async function importAesGcm(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", own(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function aesGcmEncrypt(key: CryptoKey, data: Uint8Array): Promise<Bytes> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, own(data)));
  return concat(iv, ct);
}

export async function aesGcmDecrypt(key: CryptoKey, blob: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: own(blob.subarray(0, 12)) }, key, own(blob.subarray(12))));
}

export async function importRsaOaepPrivate(pkcs8: Uint8Array, hash: "SHA-1" | "SHA-256" = "SHA-1"): Promise<CryptoKey> {
  return subtle.importKey("pkcs8", own(pkcs8), { name: "RSA-OAEP", hash }, false, ["decrypt"]);
}

export async function importRsaOaepPublic(spki: Uint8Array, hash: "SHA-1" | "SHA-256" = "SHA-1"): Promise<CryptoKey> {
  return subtle.importKey("spki", own(spki), { name: "RSA-OAEP", hash }, false, ["encrypt"]);
}

export async function rsaOaepDecrypt(key: CryptoKey, data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.decrypt({ name: "RSA-OAEP" }, key, own(data)));
}

export async function rsaOaepEncrypt(key: CryptoKey, data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP" }, key, own(data)));
}

/** Generates a 2048-bit RSA-OAEP-SHA1 key pair (used when an account has no key pair yet). */
export async function generateRsaKeyPair(): Promise<{ publicSpki: Bytes; privatePkcs8: Bytes }> {
  const kp = await subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
    true,
    ["encrypt", "decrypt"],
  );
  return {
    publicSpki: new Uint8Array(await subtle.exportKey("spki", kp.publicKey)),
    privatePkcs8: new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey)),
  };
}
