// Bitwarden "EncString" parsing and (de)cryption. Parsing is tolerant: a malformed value
// throws EncStringError for that one field, which callers turn into a per-item error
// instead of failing the whole vault (the official 2026.7 client emptied vaults this way).
import { aesCbcDecrypt, aesCbcEncrypt, hmac, rsaOaepDecrypt, rsaOaepEncrypt } from "./primitives.ts";
import { SymKey } from "./symkey.ts";
import { concat, equalBytes, fromB64, fromUtf8, randomBytes, toB64, utf8 } from "../util/bytes.ts";

export const EncType = {
  AesCbc256_B64: 0,
  AesCbc128_HmacSha256_B64: 1,
  AesCbc256_HmacSha256_B64: 2,
  Rsa2048_OaepSha256_B64: 3,
  Rsa2048_OaepSha1_B64: 4,
  Rsa2048_OaepSha256_HmacSha256_B64: 5,
  Rsa2048_OaepSha1_HmacSha256_B64: 6,
  CoseEncrypt0: 7,
} as const;
export type EncType = (typeof EncType)[keyof typeof EncType];

export class EncStringError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "EncStringError";
  }
}

export interface ParsedEnc {
  type: EncType;
  iv?: Uint8Array<ArrayBuffer>;
  data: Uint8Array<ArrayBuffer>;
  mac?: Uint8Array<ArrayBuffer>;
}

export function parseEnc(s: string): ParsedEnc {
  if (typeof s !== "string" || s.length === 0) throw new EncStringError("empty EncString");
  let type: EncType;
  let body: string;
  const dot = s.indexOf(".");
  if (dot > 0 && dot < 3) {
    type = Number(s.slice(0, dot)) as EncType;
    body = s.slice(dot + 1);
  } else {
    // Legacy un-prefixed format: three parts = type 2, two parts = type 0.
    body = s;
    type = s.split("|").length === 3 ? EncType.AesCbc256_HmacSha256_B64 : EncType.AesCbc256_B64;
  }
  const p = body.split("|");
  try {
    switch (type) {
      case EncType.AesCbc256_B64:
        if (p.length !== 2) break;
        return { type, iv: fromB64(p[0]), data: fromB64(p[1]) };
      case EncType.AesCbc128_HmacSha256_B64:
      case EncType.AesCbc256_HmacSha256_B64:
        if (p.length !== 3) break;
        return { type, iv: fromB64(p[0]), data: fromB64(p[1]), mac: fromB64(p[2]) };
      case EncType.Rsa2048_OaepSha256_B64:
      case EncType.Rsa2048_OaepSha1_B64:
        if (p.length !== 1) break;
        return { type, data: fromB64(p[0]) };
      case EncType.Rsa2048_OaepSha256_HmacSha256_B64:
      case EncType.Rsa2048_OaepSha1_HmacSha256_B64:
        if (p.length !== 2) break;
        return { type, data: fromB64(p[0]), mac: fromB64(p[1]) };
      case EncType.CoseEncrypt0:
        return { type, data: fromB64(p[0]) };
    }
  } catch {
    throw new EncStringError(`bad base64 in EncString type ${type}`);
  }
  throw new EncStringError(`malformed EncString (type ${type}, ${p.length} parts)`);
}

export async function decryptBytes(s: string, key: SymKey): Promise<Uint8Array<ArrayBuffer>> {
  const e = parseEnc(s);
  switch (e.type) {
    case EncType.AesCbc256_HmacSha256_B64: {
      if (!key.mac) throw new EncStringError("type 2 EncString needs a 64-byte key");
      const mac = await hmac(await key.hmac(), concat(e.iv!, e.data));
      if (!equalBytes(mac, e.mac!)) throw new EncStringError("MAC mismatch");
      return aesCbcDecrypt(await key.aes(), e.iv!, e.data);
    }
    case EncType.AesCbc256_B64:
      // Only very old accounts have these (protected user key wrapped directly by the master key).
      return aesCbcDecrypt(await key.aes(), e.iv!, e.data);
    case EncType.CoseEncrypt0:
      throw new EncStringError("COSE (v2) encryption is not supported yet");
    default:
      throw new EncStringError(`EncString type ${e.type} is not symmetric`);
  }
}

export async function decryptString(s: string, key: SymKey): Promise<string> {
  return fromUtf8(await decryptBytes(s, key));
}

/** Decrypts when present; returns null for null/undefined/empty. */
export async function decryptOpt(s: string | null | undefined, key: SymKey): Promise<string | null> {
  return s ? decryptString(s, key) : null;
}

export async function encryptBytes(data: Uint8Array, key: SymKey): Promise<string> {
  const iv = randomBytes(16);
  const ct = await aesCbcEncrypt(await key.aes(), iv, data);
  const mac = await hmac(await key.hmac(), concat(iv, ct));
  return `2.${toB64(iv)}|${toB64(ct)}|${toB64(mac)}`;
}

export function encryptString(s: string, key: SymKey): Promise<string> {
  return encryptBytes(utf8(s), key);
}

export async function encryptOpt(s: string | null | undefined, key: SymKey): Promise<string | null> {
  return s == null || s === "" ? null : encryptString(s, key);
}

export async function rsaDecrypt(s: string, privateKey: CryptoKey, privateKeySha256?: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  const e = parseEnc(s);
  switch (e.type) {
    case EncType.Rsa2048_OaepSha1_B64:
    case EncType.Rsa2048_OaepSha1_HmacSha256_B64:
      return rsaOaepDecrypt(privateKey, e.data);
    case EncType.Rsa2048_OaepSha256_B64:
    case EncType.Rsa2048_OaepSha256_HmacSha256_B64:
      if (!privateKeySha256) throw new EncStringError("RSA-OAEP-SHA256 key not available");
      return rsaOaepDecrypt(privateKeySha256, e.data);
    default:
      throw new EncStringError(`EncString type ${e.type} is not RSA`);
  }
}

export async function rsaEncrypt(data: Uint8Array, publicKey: CryptoKey): Promise<string> {
  return `4.${toB64(await rsaOaepEncrypt(publicKey, data))}`;
}

// ---- EncArrayBuffer (attachments / Send files): [type:1][iv:16][mac:32][ct] ----

export async function encryptBuffer(data: Uint8Array, key: SymKey): Promise<Uint8Array<ArrayBuffer>> {
  const iv = randomBytes(16);
  const ct = await aesCbcEncrypt(await key.aes(), iv, data);
  const mac = await hmac(await key.hmac(), concat(iv, ct));
  return concat(new Uint8Array([EncType.AesCbc256_HmacSha256_B64]), iv, mac, ct);
}

export async function decryptBuffer(buf: Uint8Array, key: SymKey): Promise<Uint8Array<ArrayBuffer>> {
  if (buf.length < 1 + 16 + 32 + 16) throw new EncStringError("encrypted buffer too short");
  const type = buf[0];
  if (type !== EncType.AesCbc256_HmacSha256_B64) throw new EncStringError(`unsupported buffer type ${type}`);
  const iv = buf.slice(1, 17);
  const mac = buf.slice(17, 49);
  const ct = buf.slice(49);
  const want = await hmac(await key.hmac(), concat(iv, ct));
  if (!equalBytes(want, mac)) throw new EncStringError("MAC mismatch");
  return aesCbcDecrypt(await key.aes(), iv, ct);
}
