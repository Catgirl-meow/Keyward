// The WebAuthn client half: what a browser checks and builds around the authenticator. Requests
// arrive in the JSON form of the WebAuthn options (binary fields as base64url), because they
// cross extension messaging; responses go back in the JSON form too.
// User verification: a click in Keyward's dialog while the vault is unlocked (with the master
// password or PIN) counts as verified, as in Bitwarden and other vault-based providers.
import { parse } from "tldts";
import type { Fido2View } from "../vault/types.ts";
import { equalBytes, fromB64Url, toB64Url, utf8 } from "../util/bytes.ts";
import { credentialIdBytes, type NewPasskey } from "./authenticator.ts";

export interface CredentialDescriptorJSON {
  type: string;
  id: string;
  transports?: string[];
}

export interface CreateOptionsJSON {
  rp: { id?: string; name?: string };
  user: { id: string; name?: string; displayName?: string };
  challenge: string;
  pubKeyCredParams?: { type: string; alg: number }[];
  timeout?: number;
  excludeCredentials?: CredentialDescriptorJSON[];
  authenticatorSelection?: { authenticatorAttachment?: string; residentKey?: string; requireResidentKey?: boolean; userVerification?: string };
  attestation?: string;
  extensions?: Record<string, unknown>;
}

export interface GetOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: CredentialDescriptorJSON[];
  userVerification?: string;
  extensions?: Record<string, unknown>;
  /** "conditional": the page offers passkeys in its sign-in field's autofill */
  mediation?: string;
}

export type WebAuthnErrorName = "NotAllowedError" | "SecurityError" | "TypeError" | "InvalidStateError" | "NotSupportedError";
/** `fallback`: not ours to answer; the page's request goes to the browser (security keys, phones). */
export type Refusal = { fallback: string } | { error: WebAuthnErrorName; message: string };

const fail = (error: WebAuthnErrorName, message: string): Refusal => ({ error, message });

/** https, or http on localhost names (what browsers treat as secure for WebAuthn). */
export function secureOrigin(origin: string): URL | null {
  let u: URL;
  try {
    u = new URL(origin);
  } catch {
    return null;
  }
  if (u.protocol === "https:") return u;
  if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname.endsWith(".localhost"))) return u;
  return null;
}

/** The relying party id for `origin`: the requested one if it's the origin's host or a parent
 * of it that isn't a public suffix (no "com", "co.uk" or "github.io"). */
export function resolveRpId(origin: string, requested?: string | null): { rpId: string } | Refusal {
  const u = secureOrigin(origin);
  if (!u) return { fallback: "insecure origin" };
  const host = u.hostname.toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith("[")) return { fallback: "IP address origin" };
  const id = (requested ?? host).toLowerCase().replace(/\.$/, "");
  if (!id || !(host === id || host.endsWith("." + id))) return fail("SecurityError", `"${id}" is not a valid relying party id for ${host}`);
  const p = parse(id, { allowPrivateDomains: true });
  if (id !== "localhost" && (p.publicSuffix === id || !p.domain && !id.endsWith(".localhost"))) {
    return fail("SecurityError", `"${id}" is a public suffix`);
  }
  return { rpId: id };
}

export function clientDataJSON(type: "webauthn.create" | "webauthn.get", challenge: string, origin: string, crossOrigin = false, topOrigin?: string): Uint8Array {
  const o: Record<string, unknown> = { type, challenge, origin, crossOrigin };
  if (crossOrigin && topOrigin) o.topOrigin = topOrigin;
  return utf8(JSON.stringify(o));
}

const bytes = (s: unknown): Uint8Array | null => {
  if (typeof s !== "string") return null;
  try {
    return fromB64Url(s);
  } catch {
    return null;
  }
};

export interface CreateRequest {
  rpId: string;
  rpName: string | null;
  userHandle: Uint8Array;
  userName: string | null;
  userDisplayName: string | null;
  challenge: string;
  discoverable: boolean;
  exclude: Uint8Array[];
  credProps: boolean;
}

export function parseCreate(o: CreateOptionsJSON, origin: string): CreateRequest | Refusal {
  if (!o || typeof o !== "object" || !o.rp || !o.user) return fail("TypeError", "rp and user are required");
  const rp = resolveRpId(origin, o.rp.id);
  if (!("rpId" in rp)) return rp;
  const params = o.pubKeyCredParams ?? [];
  if (params.length && !params.some((p) => p?.type === "public-key" && p.alg === -7)) return { fallback: "no ES256 in pubKeyCredParams" };
  const sel = o.authenticatorSelection ?? {};
  if (sel.authenticatorAttachment === "cross-platform") return { fallback: "the site asks for a security key" };
  const userHandle = bytes(o.user.id);
  if (!userHandle || userHandle.length < 1 || userHandle.length > 64) return fail("TypeError", "user.id must be 1 to 64 bytes");
  if (!bytes(o.challenge)) return fail("TypeError", "challenge is required");
  return {
    rpId: rp.rpId,
    rpName: o.rp.name ?? null,
    userHandle,
    userName: o.user.name ?? null,
    userDisplayName: o.user.displayName ?? null,
    challenge: o.challenge,
    // Bitwarden's rule: "required" or "preferred" (or the legacy requireResidentKey) makes it discoverable.
    discoverable: sel.residentKey === "required" || sel.residentKey === "preferred" || (sel.residentKey === undefined && sel.requireResidentKey === true),
    exclude: (o.excludeCredentials ?? []).map((d) => bytes(d?.id)).filter((b): b is Uint8Array => !!b),
    credProps: o.extensions?.credProps === true,
  };
}

export interface GetRequest {
  rpId: string;
  challenge: string;
  allow: Uint8Array[];
}

export function parseGet(o: GetOptionsJSON, origin: string): GetRequest | Refusal {
  if (!o || typeof o !== "object") return fail("TypeError", "publicKey options are required");
  const rp = resolveRpId(origin, o.rpId);
  if (!("rpId" in rp)) return rp;
  if (!bytes(o.challenge)) return fail("TypeError", "challenge is required");
  return { rpId: rp.rpId, challenge: o.challenge, allow: (o.allowCredentials ?? []).map((d) => bytes(d?.id)).filter((b): b is Uint8Array => !!b) };
}

const hasId = (f: Fido2View, ids: Uint8Array[]) => {
  const raw = credentialIdBytes(f.credentialId);
  return !!raw && ids.some((x) => equalBytes(x, raw));
};

/** Passkeys that may answer a get(): listed ones, or (no list) the discoverable ones. */
export const usable = (f: Fido2View, r: GetRequest) => f.rpId === r.rpId && (r.allow.length ? hasId(f, r.allow) : f.discoverable);

/** A create() whose excludeCredentials names a passkey the vault already holds for this site. */
export const excluded = (f: Fido2View, r: CreateRequest) => f.rpId === r.rpId && hasId(f, r.exclude);

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  type: "public-key";
  authenticatorAttachment: "platform";
  response: { clientDataJSON: string; attestationObject: string; authenticatorData: string; transports: string[]; publicKey: string; publicKeyAlgorithm: number };
  clientExtensionResults: Record<string, unknown>;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  type: "public-key";
  authenticatorAttachment: "platform";
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle: string | null };
  clientExtensionResults: Record<string, unknown>;
}

export function registrationJSON(k: NewPasskey, att: { authenticatorData: Uint8Array; attestationObject: Uint8Array }, clientData: Uint8Array, r: CreateRequest): RegistrationResponseJSON {
  const id = toB64Url(k.rawId);
  return {
    id,
    rawId: id,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: toB64Url(clientData),
      attestationObject: toB64Url(att.attestationObject),
      authenticatorData: toB64Url(att.authenticatorData),
      transports: ["hybrid", "internal"],
      publicKey: toB64Url(k.pub.spki),
      publicKeyAlgorithm: -7,
    },
    clientExtensionResults: r.credProps ? { credProps: { rk: r.discoverable } } : {},
  };
}

export function authenticationJSON(rawId: Uint8Array, a: { authenticatorData: Uint8Array; signature: Uint8Array; userHandle: Uint8Array | null }, clientData: Uint8Array): AuthenticationResponseJSON {
  const id = toB64Url(rawId);
  return {
    id,
    rawId: id,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: toB64Url(clientData),
      authenticatorData: toB64Url(a.authenticatorData),
      signature: toB64Url(a.signature),
      userHandle: a.userHandle ? toB64Url(a.userHandle) : null,
    },
    clientExtensionResults: {},
  };
}
