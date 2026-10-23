// PIN unlock. The PIN key is KDF(pin, random salt) with the account's KDF parameters, stretched.
// `protectedPin` (PIN encrypted with the user key) lets us re-create the session-only wrap
// after a master-password unlock, like the official client.
import { decryptBytes, decryptString, encryptBytes, encryptString } from "../core/crypto/encstring.ts";
import { deriveMasterKey, stretchKey, type Argon2Fn, type Kdf } from "../core/crypto/kdf.ts";
import { SymKey } from "../core/crypto/symkey.ts";
import { randomBytes, toB64 } from "../core/util/bytes.ts";
import { loadPolicy } from "./policy.ts";
import { local, session } from "./storage.ts";

interface PinState {
  salt: string;
  kdf: Kdf;
  protectedPin: string;
  /** set only when "PIN survives browser restart" is on */
  persistentWrap: string | null;
  failures: number;
}

const MAX_FAILURES = 5;

async function pinKey(pin: string, salt: string, kdf: Kdf, argon2?: Argon2Fn): Promise<SymKey> {
  return stretchKey(await deriveMasterKey(pin, salt, kdf, argon2));
}

export async function setPin(accountId: string, pin: string, userKey: SymKey, kdf: Kdf, survivesRestart: boolean, argon2?: Argon2Fn): Promise<void> {
  const salt = toB64(randomBytes(16));
  const k = await pinKey(pin, salt, kdf, argon2);
  const wrap = await encryptBytes(userKey.raw, k);
  const state: PinState = { salt, kdf, protectedPin: await encryptString(pin, userKey), persistentWrap: survivesRestart ? wrap : null, failures: 0 };
  await local.set(`pin:${accountId}`, state);
  await session.set(`pinSession:${accountId}`, wrap);
}

export async function clearPin(accountId: string): Promise<void> {
  await local.remove(`pin:${accountId}`);
  await session.remove(`pinSession:${accountId}`);
}

export async function hasPinConfigured(accountId: string): Promise<boolean> {
  return !!(await local.get(`pin:${accountId}`));
}

/** PIN unlock is possible right now (session wrap present, or persistent wrap enabled). */
export async function pinAvailable(accountId: string): Promise<boolean> {
  if ((await loadPolicy(accountId))?.removePin) return false;
  const st = await local.get<PinState>(`pin:${accountId}`);
  if (!st) return false;
  return !!(st.persistentWrap || (await session.get(`pinSession:${accountId}`)));
}

export class PinError extends Error {
  remaining: number;
  constructor(msg: string, remaining: number) {
    super(msg);
    this.remaining = remaining;
  }
}

export async function unlockWithPin(accountId: string, pin: string, argon2?: Argon2Fn): Promise<SymKey> {
  const st = await local.get<PinState>(`pin:${accountId}`);
  const wrap = st?.persistentWrap ?? (await session.get<string>(`pinSession:${accountId}`));
  if (!st || !wrap) throw new PinError("PIN unlock is not available — use your master password", 0);
  try {
    const key = new SymKey(await decryptBytes(wrap, await pinKey(pin, st.salt, st.kdf, argon2)));
    if (st.failures) await local.set(`pin:${accountId}`, { ...st, failures: 0 });
    return key;
  } catch {
    const failures = st.failures + 1;
    if (failures >= MAX_FAILURES) {
      await clearPin(accountId);
      throw new PinError("Too many wrong PINs — PIN unlock was turned off", 0);
    }
    await local.set(`pin:${accountId}`, { ...st, failures });
    throw new PinError(`Wrong PIN (${MAX_FAILURES - failures} attempts left)`, MAX_FAILURES - failures);
  }
}

/** After a master-password unlock: rebuild the session-only PIN wrap from protectedPin. */
export async function restorePinSession(accountId: string, userKey: SymKey, argon2?: Argon2Fn): Promise<void> {
  const st = await local.get<PinState>(`pin:${accountId}`);
  if (!st || (await session.get(`pinSession:${accountId}`))) return;
  try {
    const pin = await decryptString(st.protectedPin, userKey);
    const wrap = await encryptBytes(userKey.raw, await pinKey(pin, st.salt, st.kdf, argon2));
    await session.set(`pinSession:${accountId}`, wrap);
  } catch {
    // Stale PIN state (e.g. key rotation): drop it.
    await clearPin(accountId);
  }
}
