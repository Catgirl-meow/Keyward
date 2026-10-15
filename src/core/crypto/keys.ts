// Bitwarden key hierarchy: master key → (stretched) → user key → RSA private key → org keys,
// and per-item keys wrapped by the user/org key.
import { decryptBytes, encryptBytes, parseEnc, rsaDecrypt, EncType, EncStringError } from "./encstring.ts";
import { importRsaOaepPrivate } from "./primitives.ts";
import { stretchKey } from "./kdf.ts";
import { SymKey } from "./symkey.ts";

export async function decryptUserKey(protectedKey: string, masterKey: Uint8Array): Promise<SymKey> {
  const t = parseEnc(protectedKey).type;
  if (t === EncType.AesCbc256_B64) {
    // Legacy accounts: user key encrypted directly with the 32-byte master key.
    return new SymKey(await decryptBytes(protectedKey, new SymKey(masterKey)));
  }
  const stretched = await stretchKey(masterKey);
  return new SymKey(await decryptBytes(protectedKey, stretched));
}

export async function wrapUserKey(userKey: SymKey, masterKey: Uint8Array): Promise<string> {
  return encryptBytes(userKey.raw, await stretchKey(masterKey));
}

export interface PrivateKeyPair {
  pkcs8: Uint8Array;
  sha1: CryptoKey;
  sha256: CryptoKey;
}

export async function decryptPrivateKey(encPrivateKey: string, userKey: SymKey): Promise<PrivateKeyPair> {
  const pkcs8 = await decryptBytes(encPrivateKey, userKey);
  const [sha1, sha256] = await Promise.all([importRsaOaepPrivate(pkcs8, "SHA-1"), importRsaOaepPrivate(pkcs8, "SHA-256")]);
  return { pkcs8, sha1, sha256 };
}

export async function decryptOrgKey(encOrgKey: string, priv: PrivateKeyPair): Promise<SymKey> {
  return new SymKey(await rsaDecrypt(encOrgKey, priv.sha1, priv.sha256));
}

/** An item's own key (cipher key encryption), wrapped by the user or org key. */
export async function unwrapItemKey(encKey: string, parent: SymKey): Promise<SymKey> {
  const raw = await decryptBytes(encKey, parent);
  if (raw.length !== 64) throw new EncStringError(`item key has length ${raw.length}`);
  return new SymKey(raw);
}

export async function wrapItemKey(itemKey: SymKey, parent: SymKey): Promise<string> {
  return encryptBytes(itemKey.raw, parent);
}
