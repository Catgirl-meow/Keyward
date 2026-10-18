// Node-side helpers for talking to the local Vaultwarden: register accounts, log in, import items,
// read mail from mailpit. Uses the extension's own core modules, so tests exercise the same crypto.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Api, serverUrls, type Tokens } from "../../src/core/api/client.ts";
import { startLogin, submitLogin, type LoginSuccess } from "../../src/core/auth/login.ts";
import { encryptBytes, encryptString, rsaEncrypt } from "../../src/core/crypto/encstring.ts";
import { deriveMasterKey, KdfType, masterPasswordHash, type Argon2Fn, type Kdf } from "../../src/core/crypto/kdf.ts";
import { decryptUserKey, wrapUserKey } from "../../src/core/crypto/keys.ts";
import { generateRsaKeyPair, importRsaOaepPublic } from "../../src/core/crypto/primitives.ts";
import { SymKey } from "../../src/core/crypto/symkey.ts";
import { encryptCipher, type KeyRing } from "../../src/core/vault/cipher.ts";
import type { CipherView } from "../../src/core/vault/types.ts";
import { otpCode, parseOtp } from "../../src/core/totp/totp.ts";
import { fromB64, toB64 } from "../../src/core/util/bytes.ts";

export const SERVER = process.env.KW_SERVER ?? "http://localhost:8087";
export const MAILPIT = process.env.KW_MAILPIT ?? "http://localhost:8025";

const require = createRequire(import.meta.url);
let argonFn: Promise<(p: any) => Uint8Array> | null = null;
export const nodeArgon2: Argon2Fn = async (p) => {
  argonFn ??= (async () => {
    const setup = (await import("argon2id/lib/setup.js")).default;
    const dir = require.resolve("argon2id/dist/simd.wasm").replace(/simd\.wasm$/, "");
    const load = (f: string) => (imp: WebAssembly.Imports) => WebAssembly.instantiate(readFileSync(dir + f), imp);
    return setup(load("simd.wasm"), load("no-simd.wasm"));
  })();
  return (await argonFn)(p);
};

export function api(tokens?: Tokens | null): Api {
  let t = tokens ?? null;
  return new Api(
    serverUrls(SERVER),
    { deviceType: 2, deviceName: "chrome", deviceId: "11111111-2222-4333-8444-555555555555", clientVersion: "2026.9.3" } as any,
    { get: async () => t, set: async (v) => void (t = v) },
  );
}

export const PBKDF2: Kdf = { type: KdfType.PBKDF2_SHA256, iterations: 600_000, memory: null, parallelism: null };
export const ARGON2: Kdf = { type: KdfType.Argon2id, iterations: 3, memory: 64, parallelism: 4 };

export function randomPassword(): string {
  const a = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return Array.from(crypto.getRandomValues(new Uint8Array(20)), (b) => a[b % a.length]).join("") + "-kw1";
}

/** Registers an account the way the official web vault does. Returns false if it already exists. */
export async function register(email: string, password: string, kdf: Kdf = PBKDF2, name = email.split("@")[0]): Promise<boolean> {
  const mk = await deriveMasterKey(password, email, kdf, nodeArgon2);
  const hash = await masterPasswordHash(mk, password, 1);
  const userKey = SymKey.random();
  const { publicSpki, privatePkcs8 } = await generateRsaKeyPair();
  const body = {
    email,
    name,
    masterPasswordHash: hash,
    masterPasswordHint: null,
    key: await wrapUserKey(userKey, mk),
    kdf: kdf.type,
    kdfIterations: kdf.iterations,
    kdfMemory: kdf.memory,
    kdfParallelism: kdf.parallelism,
    keys: { publicKey: toB64(publicSpki), encryptedPrivateKey: await encryptBytes(privatePkcs8, userKey) },
  };
  const headers = { "Content-Type": "application/json", Accept: "application/json", "Bitwarden-Client-Name": "web", "Bitwarden-Client-Version": "2026.9.3" };
  const post = (path: string, b: unknown) => fetch(SERVER + path, { method: "POST", headers, body: JSON.stringify(b) });
  const failed = async (r: Response) => {
    const text = await r.text();
    if (/already exists|registration not allowed/i.test(text)) return false;
    throw new Error(`register ${email}: ${r.status} ${text.slice(0, 200)}`);
  };
  // Current flow (Vaultwarden 1.37.4 dropped /accounts/register): ask for a verification token,
  // which a server without SIGNUPS_VERIFY hands back at once, then finish with it.
  const v = await post("/identity/accounts/register/send-verification-email", { email, name });
  if (v.status !== 404) {
    if (!v.ok) return failed(v);
    const raw = await v.text();
    const token = raw.startsWith('"') ? JSON.parse(raw) : raw;
    const r = await post("/identity/accounts/register/finish", { ...body, emailVerificationToken: token });
    return r.ok ? true : failed(r);
  }
  for (const path of ["/identity/accounts/register", "/api/accounts/register"]) {
    const r = await post(path, body);
    if (r.status === 404) continue;
    return r.ok ? true : failed(r);
  }
  throw new Error("no register endpoint");
}

export interface Session {
  api: Api;
  login: LoginSuccess;
  ring: KeyRing;
}

export async function login(email: string, password: string): Promise<Session> {
  const a = api();
  const attempt = await startLogin(a, email, password, nodeArgon2);
  const out = await submitLogin(a, attempt);
  if (out.kind !== "success") throw new Error(`login ${email}: 2FA required`);
  await a.tokens!.set(out.tokens);
  const user = await decryptUserKey(out.protectedUserKey, out.masterKey);
  return { api: a, login: out, ring: { user, orgs: new Map() } };
}

/** Bulk import (same endpoint as the web vault's importer). Folder names map to items by index. */
export async function importItems(s: Session, items: (CipherView & { folder?: string })[], folders: string[] = []): Promise<void> {
  for (let i = 0; i < items.length; i += 500) {
    const chunk = items.slice(i, i + 500);
    const ciphers = await Promise.all(chunk.map(async (v) => (await encryptCipher(v, s.ring, { useItemKey: true, encryptedFor: s.login.userId })).body));
    const folderRelationships = chunk.flatMap((v, k) => (v.folder && folders.includes(v.folder) ? [{ key: k, value: folders.indexOf(v.folder) }] : []));
    await s.api.post("/ciphers/import", {
      ciphers,
      folders: await Promise.all(folders.map(async (name) => ({ name: await encryptString(name, s.ring.user) }))),
      folderRelationships,
    });
    if (i === 0 && items.length > 500) folders = []; // folders are created once; later chunks go unfiled
  }
}

export async function sync(s: Session): Promise<any> {
  return s.api.get("/sync?excludeDomains=true");
}

// ---------------------------------------------------------------- mailpit
export async function latestMailTo(to: string, since = 0, timeoutMs = 15_000): Promise<{ subject: string; text: string } | null> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const r = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}&limit=5`).then((x) => x.json());
    const m = (r.messages ?? []).find((x: any) => new Date(x.Created).getTime() >= since);
    if (m) {
      const full = await fetch(`${MAILPIT}/api/v1/message/${m.ID}`).then((x) => x.json());
      return { subject: full.Subject, text: full.Text ?? "" };
    }
    await new Promise((res) => setTimeout(res, 300));
  }
  return null;
}

// ---------------------------------------------------------------- two-factor setup

export async function totpNow(secret: string, offsetSec = 0): Promise<string> {
  return (await otpCode(parseOtp(secret)!, Date.now() + offsetSec * 1000)).code;
}

async function mpHash(s: Session, password: string) {
  return masterPasswordHash(s.login.masterKey, password, 1);
}

/** Turns on authenticator 2FA with a known secret (32 base32 chars, as Vaultwarden requires). */
export async function enableAuthenticator(s: Session, password: string, secret: string): Promise<void> {
  const masterPasswordHash = await mpHash(s, password);
  await s.api.post("/two-factor/get-authenticator", { masterPasswordHash });
  await s.api.post("/two-factor/authenticator", { key: secret, token: await totpNow(secret), masterPasswordHash });
}

/** Turns on email 2FA, reading the setup code from mailpit. */
export async function enableEmail2fa(s: Session, password: string, email: string): Promise<void> {
  const masterPasswordHash = await mpHash(s, password);
  const since = Date.now() - 1000;
  await s.api.post("/two-factor/send-email", { email, masterPasswordHash });
  const mail = await latestMailTo(email, since);
  const token = mail?.text.match(/\b(\d{6})\b/)?.[1];
  if (!token) throw new Error("no setup code mail");
  await s.api.put("/two-factor/email", { email, token, masterPasswordHash });
}

export function uniqueEmail(tag: string): string {
  return `${tag}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}@keyward.test`;
}

/** Body for PUT /api/two-factor/webauthn from a PublicKeyCredential serialized in the page. */
export async function enableWebauthn(s: Session, password: string, register: (options: any) => Promise<any>): Promise<void> {
  const masterPasswordHash = await mpHash(s, password);
  const options = await s.api.post("/two-factor/get-webauthn-challenge", { masterPasswordHash });
  const deviceResponse = await register(options);
  await s.api.put("/two-factor/webauthn", { id: 1, name: "Virtual key", masterPasswordHash, deviceResponse });
}

// ---------------------------------------------------------------- organizations

/** Creates an organization (free plan) with one collection; adds its key to the session's ring. */
export async function createOrg(s: Session, name: string, collection = "Shared"): Promise<{ orgId: string; collectionId: string; orgKey: SymKey }> {
  const orgKey = SymKey.random();
  const pub = await s.api.get(`/users/${s.login.userId}/public-key`);
  const userPub = await importRsaOaepPublic(fromB64(pub.publicKey ?? pub.PublicKey));
  const { publicSpki, privatePkcs8 } = await generateRsaKeyPair();
  const org = await s.api.post("/organizations", {
    name,
    billingEmail: s.login.email,
    collectionName: await encryptString(collection, orgKey),
    key: await rsaEncrypt(orgKey.raw, userPub),
    keys: { publicKey: toB64(publicSpki), encryptedPrivateKey: await encryptBytes(privatePkcs8, orgKey) },
    planType: 0,
  });
  const cols = await s.api.get(`/organizations/${org.id}/collections`);
  s.ring.orgs.set(org.id, orgKey);
  return { orgId: org.id, collectionId: (cols.data ?? cols)[0].id, orgKey };
}

export async function createOrgItem(s: Session, v: CipherView, orgId: string, collectionIds: string[]): Promise<any> {
  const { body } = await encryptCipher({ ...v, organizationId: orgId }, s.ring, { useItemKey: true, encryptedFor: s.login.userId });
  return s.api.post("/ciphers/create", { cipher: body, collectionIds });
}
