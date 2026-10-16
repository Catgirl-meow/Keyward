// A WebAuthn relying party for the passkey tests, verified by @simplewebauthn/server (not by
// Keyward's own code). One in-memory user table per relying party id (the request's host).
//   POST /rp/reg/options {user}    → creation options (excludes the user's credentials)
//   POST /rp/reg/verify  {response} → { verified }
//   POST /rp/auth/options {user?}  → request options (allowCredentials only when user given)
//   POST /rp/auth/verify {response} → { verified, user }
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type WebAuthnCredential,
} from "@simplewebauthn/server";

interface Rp {
  users: Map<string, { id: string; creds: WebAuthnCredential[] }>;
  challenge: string | null;
  pendingUser: string | null;
}
const rps = new Map<string, Rp>();
const rpOf = (host: string) => {
  let r = rps.get(host);
  if (!r) rps.set(host, (r = { users: new Map(), challenge: null, pendingUser: null }));
  return r;
};

/** Tests: a user and credential the site knows without a registration ceremony (a passkey
 * imported into the vault directly). `userId` is the user handle, base64url. */
export function rpAddUser(rpID: string, name: string, userId: string, cred: WebAuthnCredential): void {
  rpOf(rpID).users.set(name, { id: userId, creds: [cred] });
}

export async function rpRoute(path: string, b: any, origin: string): Promise<unknown | null> {
  const rpID = new URL(origin).hostname;
  const rp = rpOf(rpID);
  switch (path) {
    case "/rp/reg/options": {
      const name = String(b.user ?? "kay");
      const u = rp.users.get(name);
      const o = await generateRegistrationOptions({
        rpName: "Keyward fixtures",
        rpID,
        userName: name,
        userDisplayName: name.toUpperCase(),
        attestationType: "none",
        excludeCredentials: (u?.creds ?? []).map((c) => ({ id: c.id, transports: c.transports })),
        authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
        supportedAlgorithmIDs: [-7, -257],
        timeout: Number(b.timeout) || 60_000,
      });
      rp.challenge = o.challenge;
      rp.pendingUser = name;
      if (!u) rp.users.set(name, { id: o.user.id, creds: [] });
      return o;
    }
    case "/rp/reg/verify": {
      const v = await verifyRegistrationResponse({ response: b.response, expectedChallenge: rp.challenge ?? "", expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: false });
      if (v.verified) rp.users.get(rp.pendingUser!)!.creds.push(v.registrationInfo.credential);
      return { verified: v.verified, backedUp: v.registrationInfo?.credentialBackedUp, aaguid: v.registrationInfo?.aaguid };
    }
    case "/rp/auth/options": {
      const u = b.user ? rp.users.get(String(b.user)) : null;
      const o = await generateAuthenticationOptions({
        rpID,
        allowCredentials: u ? u.creds.map((c) => ({ id: c.id, transports: c.transports })) : [],
        userVerification: "preferred",
        timeout: Number(b.timeout) || 60_000,
      });
      rp.challenge = o.challenge;
      return o;
    }
    case "/rp/auth/verify": {
      for (const [name, u] of rp.users) {
        const cred = u.creds.find((c) => c.id === b.response?.id);
        if (!cred) continue;
        const v = await verifyAuthenticationResponse({ response: b.response, expectedChallenge: rp.challenge ?? "", expectedOrigin: origin, expectedRPID: rpID, credential: cred, requireUserVerification: false });
        if (v.verified) cred.counter = v.authenticationInfo.newCounter;
        const userHandleOk = !b.response.response.userHandle || b.response.response.userHandle === u.id;
        return { verified: v.verified && userHandleOk, user: name };
      }
      return { verified: false, error: "unknown credential" };
    }
  }
  return null;
}
