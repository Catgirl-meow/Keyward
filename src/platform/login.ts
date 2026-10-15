// Login completion shared by pages (password / TOTP / email 2FA) and the background
// (WebAuthn 2FA runs in a separate tab, so the popup is gone by the time it finishes).
import type { Argon2Fn } from "../core/crypto/kdf.ts";
import { decryptUserKey } from "../core/crypto/keys.ts";
import { Api, serverUrls } from "../core/api/client.ts";
import { submitLogin, type LoginAttempt, type LoginOutcome, type LoginSuccess, type TwoFactorSubmit } from "../core/auth/login.ts";
import { fromB64, toB64 } from "../core/util/bytes.ts";
import { clientInfo, tokenStore, upsertAccount } from "./accounts.ts";
import { local, session } from "./storage.ts";

export interface PendingLogin {
  server: string;
  email: string;
  kdf: LoginAttempt["kdf"];
  masterKey: string; // b64, session storage only
  hash: string;
  localHash: string;
  providers: Record<number, any>;
  at: number;
}

export const lazyArgon2: Argon2Fn = async (p) => (await import("../core/crypto/argon2.ts")).argon2(p);

const rememberKey = (server: string, email: string) => `remember2fa:${serverUrls(server).base}|${email.toLowerCase()}`;

export async function rememberToken(server: string, email: string): Promise<string | null> {
  return (await local.get<string>(rememberKey(server, email))) ?? null;
}

export async function savePending(server: string, out: Extract<LoginOutcome, { kind: "twoFactor" }>): Promise<void> {
  const p: PendingLogin = {
    server,
    email: out.attempt.email,
    kdf: out.attempt.kdf,
    masterKey: toB64(out.attempt.masterKey),
    hash: out.attempt.hash,
    localHash: out.attempt.localHash,
    providers: out.providers,
    at: Date.now(),
  };
  await session.set("pendingLogin", p);
}

export async function loadPending(): Promise<PendingLogin | null> {
  const p = await session.get<PendingLogin>("pendingLogin");
  if (!p || Date.now() - p.at > 15 * 60_000) return null;
  return p;
}

export async function clearPending(): Promise<void> {
  await session.remove("pendingLogin");
}

export function attemptOf(p: PendingLogin): LoginAttempt {
  return { email: p.email, kdf: p.kdf, masterKey: fromB64(p.masterKey), hash: p.hash, localHash: p.localHash };
}

export async function apiForServer(server: string): Promise<Api> {
  return new Api(serverUrls(server), await clientInfo(), null);
}

export async function submitTwoFactor(p: PendingLogin, tf: TwoFactorSubmit): Promise<LoginOutcome> {
  return submitLogin(await apiForServer(p.server), attemptOf(p), { twoFactor: tf });
}

/** Persists account + tokens and returns the decrypted user key (b64) for the session. */
export async function finishLogin(server: string, ok: LoginSuccess): Promise<{ accountId: string; userKey: string }> {
  const userKey = await decryptUserKey(ok.protectedUserKey, ok.masterKey);
  await tokenStore(ok.userId).set(ok.tokens);
  await upsertAccount({
    id: ok.userId,
    email: ok.email,
    name: ok.name,
    server: serverUrls(server).base,
    kdf: ok.kdf,
    protectedUserKey: ok.protectedUserKey,
    localHash: ok.localHash,
    addedAt: Date.now(),
  });
  if (ok.twoFactorRememberToken) await local.set(rememberKey(server, ok.email), ok.twoFactorRememberToken);
  await local.remove(`needsLogin:${ok.userId}`);
  await clearPending();
  return { accountId: ok.userId, userKey: userKey.toB64() };
}
