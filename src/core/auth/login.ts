import { Api, ApiError, errorMessage, tokensFrom, type Tokens } from "../api/client.ts";
import { deriveMasterKey, masterPasswordHash, normalizeEmail, readKdf, type Argon2Fn, type Kdf } from "../crypto/kdf.ts";
import { decodeJwt } from "../util/json.ts";

export const TwoFactorProvider = {
  Authenticator: 0,
  Email: 1,
  Duo: 2,
  Yubikey: 3,
  U2f: 4,
  Remember: 5,
  OrganizationDuo: 6,
  WebAuthn: 7,
  RecoveryCode: 8,
} as const;

export const TWO_FACTOR_NAMES: Record<number, string> = {
  0: "Authenticator app",
  1: "Email",
  2: "Duo",
  3: "YubiKey OTP",
  6: "Duo (organization)",
  7: "Passkey / security key",
  8: "Recovery code",
};

export async function prelogin(api: Api, email: string): Promise<Kdf> {
  const body = await api.post("/accounts/prelogin", { email: normalizeEmail(email) }, { base: "identity", auth: false });
  return readKdf(body ?? {});
}

/** Everything needed to (re)submit the password grant without re-running the KDF. */
export interface LoginAttempt {
  email: string;
  kdf: Kdf;
  masterKey: Uint8Array;
  /** sent to the server (1 PBKDF2 iteration) */
  hash: string;
  /** kept locally to verify the master password offline (2 iterations, as the official client) */
  localHash: string;
}

export interface LoginSuccess {
  kind: "success";
  tokens: Tokens;
  userId: string;
  email: string;
  name: string | null;
  kdf: Kdf;
  protectedUserKey: string;
  encPrivateKey: string | null;
  masterKey: Uint8Array;
  localHash: string;
  twoFactorRememberToken: string | null;
}

export interface LoginTwoFactor {
  kind: "twoFactor";
  /** provider id → provider data (email hint, WebAuthn request options, …) */
  providers: Record<number, any>;
  attempt: LoginAttempt;
}

export type LoginOutcome = LoginSuccess | LoginTwoFactor;

export async function startLogin(api: Api, email: string, password: string, argon2?: Argon2Fn): Promise<LoginAttempt> {
  const kdf = await prelogin(api, email);
  const masterKey = await deriveMasterKey(password, email, kdf, argon2);
  const [hash, localHash] = await Promise.all([masterPasswordHash(masterKey, password, 1), masterPasswordHash(masterKey, password, 2)]);
  return { email: normalizeEmail(email), kdf, masterKey, hash, localHash };
}

export interface TwoFactorSubmit {
  provider: number;
  token: string;
  remember: boolean;
}

export async function submitLogin(
  api: Api,
  attempt: LoginAttempt,
  opts: { twoFactor?: TwoFactorSubmit; rememberToken?: string | null } = {},
): Promise<LoginOutcome> {
  const form: Record<string, string> = {
    grant_type: "password",
    username: attempt.email,
    password: attempt.hash,
    scope: "api offline_access",
    client_id: "browser",
    deviceType: String(api.client.deviceType),
    deviceIdentifier: api.client.deviceId,
    deviceName: api.client.deviceName,
  };
  if (opts.twoFactor) {
    form.twoFactorToken = opts.twoFactor.token.trim();
    form.twoFactorProvider = String(opts.twoFactor.provider);
    form.twoFactorRemember = opts.twoFactor.remember ? "1" : "0";
  } else if (opts.rememberToken) {
    form.twoFactorToken = opts.rememberToken;
    form.twoFactorProvider = String(TwoFactorProvider.Remember);
    form.twoFactorRemember = "0";
  }

  const { status, body } = await api.identityToken(form);
  if (status === 200 && body?.access_token) {
    const tokens = tokensFrom(body);
    const jwt = decodeJwt(tokens.accessToken) ?? {};
    const mpu = body.userDecryptionOptions?.masterPasswordUnlock;
    const protectedUserKey = body.key ?? mpu?.masterKeyEncryptedUserKey ?? mpu?.masterKeyWrappedUserKey;
    if (!protectedUserKey) throw new ApiError(status, "Server did not return an encrypted user key", body);
    return {
      kind: "success",
      tokens,
      userId: jwt.sub,
      email: jwt.email ?? attempt.email,
      name: jwt.name ?? null,
      kdf: body.kdf != null ? readKdf(body) : attempt.kdf,
      protectedUserKey,
      encPrivateKey: body.privateKey ?? body.accountKeys?.publicKeyEncryptionKeyPair?.wrappedPrivateKey ?? null,
      masterKey: attempt.masterKey,
      localHash: attempt.localHash,
      twoFactorRememberToken: body.twoFactorToken ?? null,
    };
  }
  const providers = body?.twoFactorProviders2;
  if (status === 400 && providers && Object.keys(providers).length) {
    const out: Record<number, any> = {};
    for (const [k, v] of Object.entries(providers)) out[Number(k)] = v;
    return { kind: "twoFactor", providers: out, attempt };
  }
  throw new ApiError(status, friendlyLoginError(body, status), body);
}

function friendlyLoginError(body: any, status: number): string {
  const msg = errorMessage(body, status);
  if (/username or password is incorrect/i.test(msg)) return "Email or master password is incorrect.";
  if (/two.?step token is invalid|invalid totp|invalid two factor/i.test(msg)) return "That code is not valid. Try again.";
  return msg;
}

export async function sendEmailCode(api: Api, attempt: LoginAttempt): Promise<void> {
  await api.post(
    "/two-factor/send-email-login",
    { email: attempt.email, masterPasswordHash: attempt.hash, deviceIdentifier: api.client.deviceId, authRequestId: null, ssoEmail2FaSessionToken: null },
    { auth: false },
  );
}

/** Preferred order when several 2FA providers are enabled (cheapest for the user first). */
export function preferredProvider(providers: Record<number, any>): number {
  for (const p of [7, 0, 3, 1, 2, 6]) if (p in providers) return p;
  return Number(Object.keys(providers)[0]);
}
