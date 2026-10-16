// SSH key items: what gets saved when a field is missing (Vaultwarden drops the whole key then),
// and keys that OpenSSH's own ssh-keygen accepts and makes.
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, test } from "vitest";
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

const hasSshKeygen = (() => {
  try {
    execFileSync("ssh-keygen", ["-h"], { stdio: "ignore" });
  } catch (e: any) {
    return e.code !== "ENOENT";
  }
  return true;
})();
describe.skipIf(!hasSshKeygen)("ssh-keygen interop", () => {
  const dir = mkdtempSync(join(tmpdir(), "keyward-ssh-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const keygen = (...args: string[]) => execFileSync("ssh-keygen", args, { encoding: "utf8" }).trim();
  const blob = (pub: string) => pub.split(/\s+/).slice(0, 2).join(" ");

  test("ssh-keygen loads a key Keyward generated: same public key and fingerprint", async () => {
    const k = await generateEd25519("kay@keyward");
    const f = join(dir, "kw_ed25519");
    writeFileSync(f, k.privateKey);
    chmodSync(f, 0o600);
    expect(blob(keygen("-y", "-f", f))).toBe(blob(k.publicKey));
    expect(keygen("-l", "-E", "sha256", "-f", f).split(" ")[1]).toBe(k.fingerprint);
  });

  test.each([
    ["ed25519", []],
    ["ecdsa", ["-b", "256"]],
    ["ecdsa", ["-b", "384"]],
    ["ecdsa", ["-b", "521"]],
    ["rsa", ["-b", "3072"]],
  ] as [string, string[]][])("Keyward reads an ssh-keygen %s key %s", async (type, bits) => {
    const f = join(dir, `id_${type}${bits[1] ?? ""}`);
    keygen("-q", "-t", type, ...bits, "-N", "", "-C", "made by ssh-keygen", "-f", f);
    const d = await describeOpenSshPrivateKey(readFileSync(f, "utf8"));
    expect(blob(d!.publicKey)).toBe(blob(readFileSync(f + ".pub", "utf8")));
    expect(d!.fingerprint).toBe(keygen("-l", "-E", "sha256", "-f", f).split(" ")[1]);
  });
});
