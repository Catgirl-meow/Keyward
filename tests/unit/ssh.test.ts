// SSH key items: what gets saved when a field is missing (Vaultwarden drops the whole key then).
import { describe, expect, test } from "vitest";
import { completeSshKey, describeOpenSshPrivateKey, generateEd25519 } from "../../src/core/ssh/keys.ts";
import { decryptCipher, emptyView, encryptCipher } from "../../src/core/vault/cipher.ts";
import { SymKey } from "../../src/core/crypto/symkey.ts";
import { CipherType } from "../../src/core/vault/types.ts";

describe("ssh key items", () => {
  test("missing fields are derived from the private or public key", async () => {
    const k = await generateEd25519("kay@mac");
    expect(await completeSshKey({ privateKey: k.privateKey, publicKey: null, keyFingerprint: null })).toEqual({
      privateKey: k.privateKey,
      publicKey: (await describeOpenSshPrivateKey(k.privateKey))!.publicKey,
      keyFingerprint: k.fingerprint,
    });
    expect((await completeSshKey({ privateKey: null, publicKey: k.publicKey, keyFingerprint: null })).keyFingerprint).toBe(k.fingerprint);
    expect(await completeSshKey({ privateKey: "not a key", publicKey: null, keyFingerprint: null })).toEqual({ privateKey: "not a key", publicKey: "", keyFingerprint: "" });
  });

  test("every field is sent encrypted, even an empty one", async () => {
    const ring = { user: SymKey.random(), orgs: new Map() };
    const v = emptyView(CipherType.SshKey, { name: "Key", sshKey: { privateKey: "pasted text", publicKey: null, keyFingerprint: null } });
    const { body } = await encryptCipher(v, ring);
    for (const f of ["privateKey", "publicKey", "keyFingerprint"]) expect(body.sshKey[f]).toMatch(/^2\./);
    const back = await decryptCipher({ ...body, id: "x" } as any, ring);
    expect(back.sshKey).toEqual({ privateKey: "pasted text", publicKey: "", keyFingerprint: "" });
  });
});
