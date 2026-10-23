// Passkey authenticator + client, checked by an independent relying-party library
// (@simplewebauthn/server) rather than by our own parser.
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { describe, expect, test } from "vitest";
import { assert as assertion, attest, createPasskey, credentialIdBytes, credentialIdString, derSignature, FLAG, publicKeyOf } from "../../src/core/passkey/authenticator.ts";
import { decode, encode } from "../../src/core/passkey/cbor.ts";
import { authenticationJSON, clientDataJSON, excluded, parseCreate, parseGet, registrationJSON, resolveRpId, usable, type CreateOptionsJSON } from "../../src/core/passkey/client.ts";
import { sha256 } from "../../src/core/crypto/primitives.ts";
import { randomBytes, toB64Url, utf8 } from "../../src/core/util/bytes.ts";

const ORIGIN = "https://login.example.com";
const createOpts = (over: Partial<CreateOptionsJSON> = {}): CreateOptionsJSON => ({
  rp: { id: "example.com", name: "Example" },
  user: { id: toB64Url(utf8("user-42")), name: "kay@example.com", displayName: "Kay" },
  challenge: toB64Url(randomBytes(32)),
  pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
  authenticatorSelection: { residentKey: "required", userVerification: "required" },
  extensions: { credProps: true },
  ...over,
});

async function register(o = createOpts()) {
  const r = parseCreate(o, ORIGIN);
  if (!("rpId" in r)) throw new Error(JSON.stringify(r));
  const k = await createPasskey(r);
  const cd = clientDataJSON("webauthn.create", r.challenge, ORIGIN);
  return { r, k, json: registrationJSON(k, await attest(k, true), cd, r) };
}

describe("registration and login verified by SimpleWebAuthn", () => {
  test("create(): attestation 'none', ES256, BE/BS set, credProps", async () => {
    const { r, k, json } = await register();
    const v = await verifyRegistrationResponse({ response: json as any, expectedChallenge: r.challenge, expectedOrigin: ORIGIN, expectedRPID: "example.com", requireUserVerification: true });
    expect(v.verified).toBe(true);
    const info = v.registrationInfo!;
    expect(info.fmt).toBe("none");
    expect(info.credential.id).toBe(json.id);
    expect(info.credentialBackedUp).toBe(true);
    expect(info.credentialDeviceType).toBe("multiDevice");
    expect(info.aaguid).toBe("d548826e-79b4-db40-a3d8-11116f7e8349");
    expect(json.clientExtensionResults).toEqual({ credProps: { rk: true } });
    expect(k.fido2).toMatchObject({ keyType: "public-key", keyAlgorithm: "ECDSA", keyCurve: "P-256", rpId: "example.com", userName: "kay@example.com", discoverable: true, counter: 0 });
  });

  test("get(): signature over authData ‖ hash(clientData) verifies with the registered key", async () => {
    const { k, json } = await register();
    const reg = await verifyRegistrationResponse({ response: json as any, expectedChallenge: () => true, expectedOrigin: ORIGIN, expectedRPID: "example.com" });
    const challenge = toB64Url(randomBytes(32));
    const g = parseGet({ challenge, rpId: "example.com", allowCredentials: [{ type: "public-key", id: json.id }] }, ORIGIN);
    if (!("rpId" in g)) throw new Error("parseGet");
    expect(usable(k.fido2, g)).toBe(true);
    const cd = clientDataJSON("webauthn.get", challenge, ORIGIN);
    const a = await assertion(k.fido2, await sha256(cd), true);
    const v = await verifyAuthenticationResponse({
      response: authenticationJSON(k.rawId, a, cd) as any,
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: "example.com",
      credential: reg.registrationInfo!.credential,
      requireUserVerification: true,
    });
    expect(v.verified).toBe(true);
    expect(a.counter).toBe(0); // synced passkeys don't count
    expect(a.userHandle && new TextDecoder().decode(a.userHandle)).toBe("user-42");
  });

  test("a passkey that already counts keeps counting", async () => {
    const { k } = await register();
    const a = await assertion({ ...k.fido2, counter: 7 }, await sha256("x"), true);
    expect(a.counter).toBe(8);
    expect(a.authenticatorData[32] & (FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS)).toBe(FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS);
  });

  test("the stored key alone gives back the public key", async () => {
    const { k } = await register();
    const p = await publicKeyOf(k.fido2);
    expect(toB64Url(p.spki)).toBe(toB64Url(k.pub.spki));
  });
});

describe("credential ids (Bitwarden storage format)", () => {
  test("GUID ↔ 16 bytes, other lengths as b64.<base64url>", () => {
    const g = "6f1c1b7e-2d55-4c1a-9d3e-0a1b2c3d4e5f";
    const raw = credentialIdBytes(g)!;
    expect(raw).toHaveLength(16);
    expect(raw[0]).toBe(0x6f);
    expect(credentialIdString(raw)).toBe(g);
    const odd = randomBytes(20);
    const s = credentialIdString(odd);
    expect(s.startsWith("b64.")).toBe(true);
    expect(credentialIdBytes(s)).toEqual(odd);
    expect(credentialIdBytes("not-an-id")).toBeNull();
  });
});

describe("client rules", () => {
  test("relying party id: the host or a parent, never a public suffix", () => {
    expect(resolveRpId("https://login.example.com")).toEqual({ rpId: "login.example.com" });
    expect(resolveRpId("https://login.example.com", "example.com")).toEqual({ rpId: "example.com" });
    expect(resolveRpId("https://login.example.com", "other.com")).toMatchObject({ error: "SecurityError" });
    expect(resolveRpId("https://example.co.uk", "co.uk")).toMatchObject({ error: "SecurityError" });
    expect(resolveRpId("https://me.github.io", "github.io")).toMatchObject({ error: "SecurityError" });
    expect(resolveRpId("http://example.com")).toMatchObject({ fallback: expect.any(String) });
    expect(resolveRpId("http://login.localhost:8090")).toEqual({ rpId: "login.localhost" });
    expect(resolveRpId("https://192.168.1.2")).toMatchObject({ fallback: expect.any(String) });
  });

  test("create(): no ES256 or a security-key request goes to the browser", () => {
    expect(parseCreate(createOpts({ pubKeyCredParams: [{ type: "public-key", alg: -257 }] }), ORIGIN)).toMatchObject({ fallback: expect.any(String) });
    expect(parseCreate(createOpts({ authenticatorSelection: { authenticatorAttachment: "cross-platform" } }), ORIGIN)).toMatchObject({ fallback: expect.any(String) });
    expect(parseCreate(createOpts({ pubKeyCredParams: [] }), ORIGIN)).toMatchObject({ rpId: "example.com" });
    expect(parseCreate(createOpts({ user: { id: toB64Url(new Uint8Array(65)) } }), ORIGIN)).toMatchObject({ error: "TypeError" });
  });

  test("discoverable follows residentKey like Bitwarden", () => {
    const d = (sel: any) => (parseCreate(createOpts({ authenticatorSelection: sel }), ORIGIN) as any).discoverable;
    expect(d({ residentKey: "required" })).toBe(true);
    expect(d({ residentKey: "preferred" })).toBe(true);
    expect(d({ residentKey: "discouraged" })).toBe(false);
    expect(d({ requireResidentKey: true })).toBe(true);
    expect(d({})).toBe(false);
  });

  test("excludeCredentials and allowCredentials match by id and rp", async () => {
    const { k, json } = await register();
    const again = parseCreate(createOpts({ excludeCredentials: [{ type: "public-key", id: json.id }] }), ORIGIN) as any;
    expect(excluded(k.fido2, again)).toBe(true);
    const other = parseGet({ challenge: "AAAA", rpId: "example.com", allowCredentials: [{ type: "public-key", id: toB64Url(randomBytes(16)) }] }, ORIGIN) as any;
    expect(usable(k.fido2, other)).toBe(false);
    const discover = parseGet({ challenge: "AAAA", rpId: "example.com" }, ORIGIN) as any;
    expect(usable(k.fido2, discover)).toBe(true);
    expect(usable({ ...k.fido2, discoverable: false }, discover)).toBe(false);
    expect(usable(k.fido2, { ...discover, rpId: "login.example.com" })).toBe(false);
  });
});

describe("CBOR and DER", () => {
  test("round trip keeps map order and types", () => {
    const m = new Map<any, any>([[1, 2], [3, -7], [-1, 1], ["fmt", "none"], ["b", Uint8Array.of(1, 2, 3)], ["l", [true, false, null, 300, 70000]]]);
    const { value, end } = decode(encode(m));
    const enc = encode(m);
    expect(end).toBe(enc.length);
    expect([...(value as Map<any, any>).keys()]).toEqual([1, 3, -1, "fmt", "b", "l"]);
    expect((value as Map<any, any>).get("l")).toEqual([true, false, null, 300, 70000]);
    expect(() => decode(enc.subarray(0, enc.length - 1))).toThrow();
  });

  test("DER pads integers whose high bit is set", () => {
    const raw = new Uint8Array(64);
    raw[0] = 0x80;
    raw[32] = 0x00;
    raw[33] = 0x01;
    const der = derSignature(raw);
    expect(der[0]).toBe(0x30);
    expect([der[2], der[3], der[4]]).toEqual([0x02, 33, 0x00]);
  });
});
