// GPG key items: Keyguard's field format (cases ported from its BitwardenGpgKeyFieldCodecTest),
// OpenPGP round trips, and the real gpg binary reading what Keyward makes and the reverse.
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, test } from "vitest";
import { decodeGpgFields, encodeGpgFields, GPG_FIELD, looksLikeGpgItem, type GpgKeyFields } from "../../src/core/gpg/fields.ts";
import { decryptText, describeKey, encryptText, generateGpgKey, PassphraseNeeded, readGpgKey, recipientsOf, signText, spacedFingerprint, unlockKey, verifyText } from "../../src/core/gpg/pgp.ts";
import { emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType, FieldType, type FieldView } from "../../src/core/vault/types.ts";

const CHUNK = 3500;
const FP = "0123456789ABCDEF0123456789ABCDEF01234567";
const key = (k: Partial<GpgKeyFields>): GpgKeyFields => ({ privateKey: null, publicKey: null, fingerprint: null, ...k });
const field = (name: string, value: string | null, type: FieldType = FieldType.Text): FieldView => ({ type, name, value, linkedId: null });
const part = (n: number) => `${GPG_FIELD.privateKey}.v1.part.${n}`;
const hash = `${GPG_FIELD.privateKey}.v1.sha256`;

describe("gpg fields (Keyguard's format)", () => {
  test("short and boundary-size keys keep one plain field", async () => {
    for (const pk of ["short key", "a".repeat(CHUNK)]) {
      expect(await encodeGpgFields(key({ privateKey: pk }), [])).toEqual([field(GPG_FIELD.privateKey, pk, FieldType.Hidden)]);
    }
  });

  test("oversized keys are split into hashed chunks, private and public separately", async () => {
    const privateKey = "a".repeat(CHUNK + 1);
    const publicKey = "b".repeat(CHUNK * 2 + 1);
    const fields = await encodeGpgFields(key({ privateKey, publicKey, fingerprint: FP }), []);
    expect(fields.map((f) => [f.name, f.type, f.value?.length])).toEqual([
      [part(1), FieldType.Hidden, CHUNK],
      [part(2), FieldType.Hidden, 1],
      [hash, FieldType.Hidden, 64],
      [`${GPG_FIELD.publicKey}.v1.part.1`, FieldType.Text, CHUNK],
      [`${GPG_FIELD.publicKey}.v1.part.2`, FieldType.Text, CHUNK],
      [`${GPG_FIELD.publicKey}.v1.part.3`, FieldType.Text, 1],
      [`${GPG_FIELD.publicKey}.v1.sha256`, FieldType.Text, 64],
      [GPG_FIELD.fingerprint, FieldType.Text, 40],
    ]);
    expect((await decodeGpgFields(fields))?.key).toEqual({ privateKey, publicKey, fingerprint: FP });
  });

  test("chunks never cut a UTF-8 character and fit the byte budget", async () => {
    const privateKey = "я🔑".repeat(1200);
    const fields = await encodeGpgFields(key({ privateKey }), []);
    for (const f of fields.filter((f) => f.name!.includes(".part."))) {
      expect(new TextEncoder().encode(f.value!).length).toBeLessThanOrEqual(CHUNK);
      expect(f.value).not.toMatch(/�/);
    }
    expect((await decodeGpgFields(fields))?.key.privateKey).toBe(privateKey);
  });

  test("chunk order comes from the indexes; the user's fields stay, duplicates too", async () => {
    const privateKey = "0123456789".repeat(800);
    const mine = field("User field", "keep me");
    const decoded = await decodeGpgFields([mine, ...(await encodeGpgFields(key({ privateKey }), [])).reverse(), mine]);
    expect(decoded?.key.privateKey).toBe(privateKey);
    expect(decoded?.rest).toEqual([mine, mine]);
  });

  test("a malformed chunk group rejects the whole key", async () => {
    const privateKey = "a".repeat(CHUNK + 1);
    const fields = await encodeGpgFields(key({ privateKey, publicKey: "public key", fingerprint: FP }), []);
    const p1 = fields.find((f) => f.name === part(1))!;
    const p2 = fields.find((f) => f.name === part(2))!;
    const h = fields.find((f) => f.name === hash)!;
    const swap = (from: FieldView, to: Partial<FieldView>) => fields.map((f) => (f === from ? { ...f, ...to } : f));
    const bad: FieldView[][] = [
      fields.filter((f) => f !== p2),
      fields.filter((f) => f !== h),
      [...fields, p1],
      [...fields, h],
      swap(p2, { name: part(3) }),
      swap(p2, { name: `${GPG_FIELD.privateKey}.v1.part.02` }),
      swap(p2, { name: `${GPG_FIELD.privateKey}.v1.unknown` }),
      swap(p2, { value: "" }),
      fields.filter((f) => f !== p2).map((f) => (f === p1 ? { ...f, value: privateKey } : f)),
      swap(p1, { type: FieldType.Text }),
      swap(p1, { linkedId: 100 }),
      swap(p1, { value: "changed" }),
      swap(h, { value: "0".repeat(64) }),
      swap(h, { value: h.value!.toUpperCase() }),
    ];
    for (const b of bad) expect(await decodeGpgFields(b)).toBeNull();
  });

  test("a matching plain field may sit next to the chunks; a different one rejects", async () => {
    const privateKey = "a".repeat(CHUNK + 1);
    const fields = await encodeGpgFields(key({ privateKey }), []);
    const same = field(GPG_FIELD.privateKey, privateKey, FieldType.Hidden);
    const ok = await decodeGpgFields([...fields, same]);
    expect(ok?.key.privateKey).toBe(privateKey);
    expect(ok?.rest).toEqual([]);
    for (const v of ["different", null]) expect(await decodeGpgFields([...fields, { ...same, value: v }])).toBeNull();
  });

  test("encoding replaces the old key fields and keeps the user's", async () => {
    const mine = field("Note", "x");
    const old = await encodeGpgFields(key({ privateKey: "a".repeat(CHUNK + 5), fingerprint: "OLD" }), [mine]);
    const next = await encodeGpgFields(key({ publicKey: "pub", fingerprint: FP }), old);
    expect(next).toEqual([field(GPG_FIELD.publicKey, "pub"), field(GPG_FIELD.fingerprint, FP), mine]);
    // An emptied key leaves only the user's fields.
    expect(await encodeGpgFields(key({}), next)).toEqual([mine]);
  });

  test("a public key alone, even in hidden fields, decodes", async () => {
    const decoded = await decodeGpgFields([field(GPG_FIELD.publicKey, "wire public key", FieldType.Hidden), field(GPG_FIELD.fingerprint, FP, FieldType.Hidden)]);
    expect(decoded).toEqual({ key: { privateKey: null, publicKey: "wire public key", fingerprint: FP }, rest: [] });
  });

  test("only secure notes are GPG items", () => {
    const fields = [field(GPG_FIELD.publicKey, "k")];
    expect(looksLikeGpgItem(emptyView(CipherType.SecureNote, { fields }))).toBe(true);
    expect(looksLikeGpgItem(emptyView(CipherType.Login, { fields }))).toBe(false);
    expect(looksLikeGpgItem(emptyView(CipherType.SecureNote, { fields: [field("keyguard.gpg.other", "x")] }))).toBe(false);
  });
});

describe("openpgp", () => {
  test("a new key: Ed25519 + Cv25519, unprotected, expiring when asked", async () => {
    const k = await generateGpgKey({ name: "Kay", email: "kay@example.test", expiresInDays: 365 });
    const info = await describeKey(await readGpgKey(k.privateKey));
    expect(info).toMatchObject({ fingerprint: k.fingerprint, algorithm: "Ed25519", userIds: ["Kay <kay@example.test>"], isPrivate: true, locked: false, revoked: false });
    expect(info.uses).toEqual(["certify", "sign"]);
    expect(info.subkeys).toMatchObject([{ algorithm: "Cv25519", uses: ["encrypt"] }]);
    expect(Math.round((Date.parse(info.expires!) - Date.parse(info.created)) / 86400e3)).toBe(365);
    expect((await describeKey(await readGpgKey(k.publicKey))).isPrivate).toBe(false);
    expect(spacedFingerprint(k.fingerprint)).toMatch(/^([0-9A-F]{4} ){9}[0-9A-F]{4}$/);
  });

  test("sign, verify, encrypt, decrypt", async () => {
    const a = await generateGpgKey({ name: "Alice", email: "", expiresInDays: null });
    const b = await generateGpgKey({ name: "", email: "bob@example.test", expiresInDays: null });
    const [aPriv, bPriv, aPub, bPub] = await Promise.all([unlockKey(a.privateKey), unlockKey(b.privateKey), readGpgKey(a.publicKey), readGpgKey(b.publicKey)]);
    const signed = await signText("Привет\nline two\n", aPriv);
    const v = await verifyText(signed, [aPub, bPub]);
    expect(v.text).toBe("Привет\nline two\n");
    expect(v.signatures).toMatchObject([{ valid: true, signer: { fingerprint: a.fingerprint, userId: "Alice" } }]);
    // Tampered text, unknown signer.
    expect((await verifyText(signed.replace("line two", "line 2"), [aPub])).signatures[0].valid).toBe(false);
    expect((await verifyText(signed, [bPub])).signatures[0]).toMatchObject({ valid: false, signer: null, error: "No public key for this signature" });
    const sig = await signText("file body", aPriv, true);
    expect((await verifyText(sig, [aPub], "file body")).signatures[0].valid).toBe(true);
    expect((await verifyText(sig, [aPub], "file b0dy")).signatures[0].valid).toBe(false);

    const enc = await encryptText("for bob", [bPub], aPriv);
    expect(await recipientsOf(enc)).toEqual([(await readGpgKey(b.publicKey)).subkeys[0].getKeyID().toHex().toUpperCase()]);
    const d = await decryptText(enc, [aPriv, bPriv], [aPub]);
    expect(d.text).toBe("for bob");
    expect(d.signatures[0].valid).toBe(true);
    await expect(decryptText(enc, [aPriv], [])).rejects.toThrow(/None of your GPG keys/);
  });

  test("a passphrase-protected key asks for its passphrase", async () => {
    const { generateKey } = await import("openpgp");
    const { privateKey } = await generateKey({ userIDs: [{ name: "P" }], passphrase: "open sesame", format: "armored" });
    expect((await describeKey(await readGpgKey(privateKey))).locked).toBe(true);
    await expect(unlockKey(privateKey)).rejects.toBeInstanceOf(PassphraseNeeded);
    await expect(unlockKey(privateKey, "nope")).rejects.toThrow(/Wrong passphrase/);
    expect((await unlockKey(privateKey, "open sesame")).isDecrypted()).toBe(true);
  });

  test("garbage is not a key", async () => {
    await expect(readGpgKey("hello")).rejects.toThrow(/Not an OpenPGP key/);
    await expect(readGpgKey("  ")).rejects.toThrow(/Paste a key/);
  });
});

// The real gpg, in a throwaway home directory.
const hasGpg = (() => {
  try {
    execFileSync("gpg", ["--version"]);
    return true;
  } catch {
    return false;
  }
})();
describe.skipIf(!hasGpg)("gpg interop", () => {
  const home = mkdtempSync(join(tmpdir(), "keyward-gpg-"));
  const gpg = (args: string[], input?: string) => execFileSync("gpg", ["--homedir", home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", ...args], { input, stdio: ["pipe", "pipe", "pipe"] }).toString();
  const gpgErr = (args: string[], input?: string) => {
    try {
      execFileSync("gpg", ["--homedir", home, "--batch", "--status-fd", "2", ...args], { input, stdio: ["pipe", "pipe", "pipe"] });
      return "";
    } catch (e: any) {
      return String(e.stderr);
    }
  };
  afterAll(() => {
    try {
      execFileSync("gpgconf", ["--homedir", home, "--kill", "all"]);
    } catch {}
    rmSync(home, { recursive: true, force: true });
  });

  test("gpg imports a Keyward key and verifies and decrypts what it made", async () => {
    const k = await generateGpgKey({ name: "Kay", email: "kay@example.test", expiresInDays: 5 * 365 });
    gpg(["--import"], k.privateKey);
    expect(gpg(["--with-colons", "--fingerprint", "kay@example.test"])).toContain(`fpr:::::::::${k.fingerprint}:`);
    const priv = await unlockKey(k.privateKey);
    const signed = await signText("signed by keyward\n", priv);
    writeFileSync(join(home, "msg.asc"), signed);
    expect(execFileSync("gpg", ["--homedir", home, "--batch", "--status-fd", "1", "--verify", join(home, "msg.asc")], { stdio: ["pipe", "pipe", "pipe"] }).toString()).toMatch(new RegExp(`GOODSIG ${k.fingerprint.slice(-16)}`));
    writeFileSync(join(home, "data.txt"), "detached body");
    writeFileSync(join(home, "data.txt.asc"), await signText("detached body", priv, true));
    expect(execFileSync("gpg", ["--homedir", home, "--batch", "--status-fd", "1", "--verify", join(home, "data.txt.asc"), join(home, "data.txt")], { stdio: ["pipe", "pipe", "pipe"] }).toString()).toContain("GOODSIG");
    const enc = await encryptText("to gpg", [await readGpgKey(k.publicKey)]);
    expect(gpg(["--decrypt"], enc)).toBe("to gpg");
    // A tampered signature is caught by gpg too.
    expect(gpgErr(["--verify"], signed.replace("signed by", "signed bY"))).toContain("BADSIG");
  });

  test("Keyward opens a gpg-made key, its signatures and its messages", async () => {
    gpg(["--quick-generate-key", "Gee <gee@example.test>", "default", "default", "never"]);
    const fp = /fpr:::::::::([0-9A-F]{40}):/.exec(gpg(["--with-colons", "--fingerprint", "gee@example.test"]))![1];
    const privateKey = gpg(["--armor", "--export-secret-keys", fp]);
    const publicKey = gpg(["--armor", "--export", fp]);
    const info = await describeKey(await readGpgKey(privateKey));
    expect(info).toMatchObject({ fingerprint: fp, userIds: ["Gee <gee@example.test>"], isPrivate: true, locked: false });
    const pub = await readGpgKey(publicKey);
    const v = await verifyText(gpg(["--clearsign", "--local-user", fp], "from gpg\n"), [pub]);
    expect(v).toMatchObject({ text: "from gpg", signatures: [{ valid: true, signer: { fingerprint: fp } }] });
    const enc = gpg(["--armor", "--encrypt", "--sign", "--local-user", fp, "--recipient", fp], "secret from gpg");
    const d = await decryptText(enc, [await unlockKey(privateKey)], [pub]);
    expect(d.text).toBe("secret from gpg");
    expect(d.signatures[0].valid).toBe(true);
  });
});
