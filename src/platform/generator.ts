// Generator preferences (shared by the generator screen, the inline menu and the background) and
// the encrypted "generated history" list.
import { decryptString, encryptString } from "../core/crypto/encstring.ts";
import type { SymKey } from "../core/crypto/symkey.ts";
import { DEFAULT_PASSPHRASE, DEFAULT_PASSWORD, type PassphraseOpts, type PasswordOpts, type UsernameKind } from "../core/generator/password.ts";
import type { ForwarderId } from "../core/generator/forwarders.ts";
import { local } from "./storage.ts";

export interface GeneratorPrefs {
  mode: "password" | "passphrase" | "username";
  password: PasswordOpts;
  passphrase: PassphraseOpts;
  username: { kind: UsernameKind | "forwarded"; email: string; domain: string; capitalize: boolean; number: boolean; forwarder: ForwarderId };
}

const DEFAULTS: GeneratorPrefs = {
  mode: "password",
  password: DEFAULT_PASSWORD,
  passphrase: DEFAULT_PASSPHRASE,
  username: { kind: "word", email: "", domain: "", capitalize: false, number: true, forwarder: "simplelogin" },
};

export async function loadGeneratorPrefs(): Promise<GeneratorPrefs> {
  const p = await local.get<Partial<GeneratorPrefs>>("generator");
  return { ...DEFAULTS, ...p, password: { ...DEFAULTS.password, ...p?.password }, passphrase: { ...DEFAULTS.passphrase, ...p?.passphrase }, username: { ...DEFAULTS.username, ...p?.username } };
}

/** Adds a generated value to the account's encrypted history (newest first, 50 kept). */
export async function rememberGenerated(accountId: string, userKey: SymKey, value: string): Promise<void> {
  const key = `genHistory:${accountId}`;
  let h: { v: string; t: number }[] = [];
  const enc = await local.get<string>(key);
  if (enc) {
    try {
      h = JSON.parse(await decryptString(enc, userKey));
    } catch {}
  }
  if (h[0]?.v === value) return;
  await local.set(key, await encryptString(JSON.stringify([{ v: value, t: Date.now() }, ...h].slice(0, 50)), userKey));
}
