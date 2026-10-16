// Export and import: every format round-trips, and browser CSVs come in as logins.
// (tests/e2e/interop.test.ts checks the same files against the official bw CLI.)
import { describe, expect, test } from "vitest";
import { SymKey } from "../../src/core/crypto/symkey.ts";
import { KdfType } from "../../src/core/crypto/kdf.ts";
import { parseCsv, toCsv } from "../../src/core/export/csv.ts";
import { exportAccountEncrypted, exportCsv, exportJson, exportPasswordProtected } from "../../src/core/export/export.ts";
import { detectFormat, ImportError, parseImport } from "../../src/core/export/import.ts";
import { emptyView, encryptCipher } from "../../src/core/vault/cipher.ts";
import { CipherType, FieldType, type CipherView } from "../../src/core/vault/types.ts";
import { encryptString } from "../../src/core/crypto/encstring.ts";

const PBKDF2 = { type: KdfType.PBKDF2_SHA256, iterations: 5000, memory: null, parallelism: null } as const;

function vault(): CipherView[] {
  const l = emptyView(CipherType.Login, {
    id: "l1", name: "Mail, \"work\"", notes: "line 1\nline 2", favorite: true, reprompt: 1, folderId: "f1",
    login: { username: "kay", password: "p,a\"s\ns", passwordRevisionDate: null, totp: "JBSWY3DPEHPK3PXP", uris: [{ uri: "https://mail.example", match: 1 }, { uri: "https://alt.example", match: null }], autofillOnPageLoad: null,
      fido2Credentials: [{ credentialId: "b64id", keyType: "public-key", keyAlgorithm: "ECDSA", keyCurve: "P-256", keyValue: "pkcs8", rpId: "mail.example", userHandle: "uh", userName: "kay", counter: 3, rpName: "Mail", userDisplayName: "Kay", discoverable: true, creationDate: "2026-01-01T00:00:00.000Z" }] },
    fields: [{ type: FieldType.Hidden, name: "pin", value: "1234", linkedId: null }],
    passwordHistory: [{ password: "old", lastUsedDate: "2025-01-01T00:00:00.000Z" }],
  });
  const n = emptyView(CipherType.SecureNote, { id: "n1", name: "Note", notes: "Кириллица 🔑" });
  const c = emptyView(CipherType.Card, { id: "c1", name: "Card", card: { cardholderName: "Kay", brand: "Visa", number: "4111111111111111", expMonth: "7", expYear: "2031", code: "123" } });
  const i = emptyView(CipherType.Identity, { id: "i1", name: "Me" });
  Object.assign(i.identity!, { firstName: "Kay", lastName: "Ward", email: "kay@example.test" });
  const k = emptyView(CipherType.SshKey, { id: "k1", name: "Key", sshKey: { privateKey: "PRIV", publicKey: "ssh-ed25519 AAAA", keyFingerprint: "SHA256:x" } });
  const org = emptyView(CipherType.SecureNote, { id: "o1", name: "Org note", organizationId: "org" });
  const gone = emptyView(CipherType.SecureNote, { id: "d1", name: "Deleted", deletedDate: "2026-01-01T00:00:00Z" });
  return [l, n, c, i, k, org, gone];
}
const folders = [{ id: "f1", name: "Work" }, { id: "f2", name: "Unused" }];

/** What survives an export: the content, not ids or dates. */
const content = (v: CipherView) => ({ type: v.type, name: v.name, notes: v.notes, favorite: v.favorite, reprompt: v.reprompt, login: v.login, card: v.card, identity: v.identity, sshKey: v.sshKey, fields: v.fields, passwordHistory: v.passwordHistory });
const personal = vault().filter((v) => v.id !== "o1" && v.id !== "d1");

describe("export and import", () => {
  test("plain JSON round-trips every type; org items and trash stay out", async () => {
    const r = await parseImport(exportJson(vault(), folders));
    expect(r.format).toBe("bitwarden_json");
    expect(r.items.map(content)).toEqual(personal.map(content));
    expect(r.folders).toEqual(["Work"]);
    expect(r.relations).toEqual([[0, 0]]);
  });

  test("password-protected JSON: right password, wrong one, none", async () => {
    const file = await exportPasswordProtected(exportJson(vault(), folders), "s3cret pass", PBKDF2);
    expect(detectFormat(file)).toBe("bitwarden_password_json");
    expect(file).not.toContain("Кириллица");
    const r = await parseImport(file, { password: "s3cret pass" });
    expect(r.items.map(content)).toEqual(personal.map(content));
    await expect(parseImport(file, { password: "nope" })).rejects.toMatchObject({ code: "password" });
    await expect(parseImport(file)).rejects.toBeInstanceOf(ImportError);
  });

  test("account-encrypted JSON opens only with the same account key", async () => {
    const user = SymKey.random();
    const ring = { user, orgs: new Map([["org", SymKey.random()]]) };
    const raws = await Promise.all(vault().map(async (v) => ({ ...(await encryptCipher(v, ring, { useItemKey: true })).body, id: v.id, organizationId: v.organizationId, deletedDate: v.deletedDate }) as any));
    const file = await exportAccountEncrypted(raws, [{ id: "f1", name: await encryptString("Work", user) }], user);
    expect(detectFormat(file)).toBe("bitwarden_encrypted_json");
    const r = await parseImport(file, { userKey: user });
    expect(r.items.map(content)).toEqual(personal.map(content));
    expect(r.folders).toEqual(["Work"]);
    await expect(parseImport(file, { userKey: SymKey.random() })).rejects.toMatchObject({ code: "account" });
  });

  test("Bitwarden CSV keeps logins and notes, with folders, fields and several websites", async () => {
    const csv = exportCsv(vault(), new Map(folders.map((f) => [f.id, f.name])));
    const r = await parseImport(csv);
    expect(r.format).toBe("bitwarden_csv");
    expect(r.items.map((v) => v.name)).toEqual(["Mail, \"work\"", "Note"]);
    const l = r.items[0];
    expect([l.login?.password, l.login?.totp, l.login?.uris.map((u) => u.uri), l.notes, l.favorite, l.reprompt]).toEqual(['p,a"s\ns', "JBSWY3DPEHPK3PXP", ["https://mail.example", "https://alt.example"], "line 1\nline 2", true, 1]);
    expect(l.fields).toEqual([{ type: FieldType.Text, name: "pin", value: "1234", linkedId: null }]);
    expect(r.folders).toEqual(["Work"]);
    expect(r.items[1].notes).toBe("Кириллица 🔑");
  });

  test("browser password CSVs", async () => {
    const chrome = "name,url,username,password,note\nexample.com,https://example.com/login,kay,pw1,\n,https://nameless.example/,u,p2,remember\n";
    const c = await parseImport(chrome);
    expect(c.format).toBe("chromium_csv");
    expect(c.items.map((v) => [v.name, v.login?.uris[0]?.uri, v.login?.username, v.login?.password, v.notes])).toEqual([
      ["example.com", "https://example.com/login", "kay", "pw1", null],
      ["nameless.example", "https://nameless.example/", "u", "p2", "remember"],
    ]);
    const firefox = '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n"https://www.mozilla.example","fox","pw""q",,"https://www.mozilla.example","{1}","1","2","3"\n';
    const f = await parseImport(firefox);
    expect(f.format).toBe("firefox_csv");
    expect([f.items[0].name, f.items[0].login?.password]).toEqual(["mozilla.example", 'pw"q']);
    const safari = "Title,URL,Username,Password,Notes,OTPAuth\nBank,https://bank.example,me,pw,,otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP\n";
    const s = await parseImport(safari);
    expect([s.format, s.items[0].name, s.items[0].login?.totp]).toEqual(["safari_csv", "Bank", "otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP"]);
  });

  test("not an export, or an empty one", async () => {
    await expect(parseImport("hello")).rejects.toMatchObject({ code: "format" });
    await expect(parseImport('{"encrypted":false,"folders":[],"items":[]}')).rejects.toMatchObject({ code: "empty" });
  });

  test("CSV: quotes, commas, line breaks, CRLF and a BOM", () => {
    const rows = [["a", 'b "q"', "c,d"], ["line\nbreak", "", " pad "]];
    expect(parseCsv("﻿" + toCsv(["x", "y", "z"], rows).replace(/\n(?=[^"]*$)/g, "\r\n"))).toEqual([["x", "y", "z"], ...rows]);
  });
});
